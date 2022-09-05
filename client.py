import base64
import hashlib
import json
import os
import re
import sys
import time

import urwid
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from twisted.internet import reactor
from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineReceiver

#########################################################################
# ****************************** GLOBALS ****************************** #
#########################################################################
# * SERVER INFORMATION:                                                 #
#   - The IPv4 of the server.                                           #
HOST = '127.0.0.1'
#   - The port it is listening.                                         #
PORT = 8888
#   - The password the server requires to connect.                      #
SERVER_PASSWD = 'thisisapassword'
#   - The AES key shared with the clients to encrypt everythig.         #
AES_KEY = 'aaaaaaaaaaaaaaaa'.encode("utf-8")
#                                                                       #
#########################################################################
# * KEYS CONFIGURATION:                                                 #
#   - The file containing the public keys of your peers, that will be   #
# used to encrypt your messages.                                        #
AUTHORIZED_KEYS = 'keys/authorized_keys'
#   - Your private RSA key, used to decrypt messages received.          #
PRIV_KEY = 'keys/id_rsa'
#   - Your private RSA key's passphrase.                                #
PASSPHRASE = ''
#                                                                       #
#########################################################################
# * CLIENT CONFIGURATION:                                               #
#   - Your default nickname.                                            #
NICKNAME = 'user'
#   - File to store messages. If left empty, logging will be disabled.  #
LOG_FILE = ''
#                                                                       #
#########################################################################
# * AES ENCRYPTION/DECRYPTION (DONT CHANGE THIS):                       #
#   - The AES object with our shared AES_KEY.                           #
CIPHER = AES.new(AES_KEY, AES.MODE_ECB)
#   - The block size for the cipher object; must be 16 per FIPS-197.    #
BLOCK_SIZE = 16
#   - The character used for padding-with a block cipher such as AES,   #
# the value you encrypt must be a multiple of BLOCK_SIZE in length.     #
# This character is used to ensure that your value is always a multiple #
# of BLOCK_SIZE.                                                        #
PADDING = '{'


def pad(s):
    """ One-liner to sufficiently pad the text to be encrypted. """
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING


def EncodeAES(s):
    """ One-liner to encrypt/encode a string """
    return base64.b64encode(CIPHER.encrypt(pad(s).encode("utf-8")))


def DecodeAES(s):
    """ One-liner to decrypt/decode a string """
    return CIPHER.decrypt(base64.b64decode(s)).rstrip(
        PADDING.encode("utf-8")).decode("utf-8")


class RSACipher():
    """
    This class handles the RSA encryption and decryption
    """

    def __init__(self, privkey, passphrase, authorized_keys):
        """
        Read a txt file with all the public keys that we want to encrypt our
        messages with
        """
        self.pubkeys = {}

        # loading up our authorized keys
        with open(authorized_keys) as f:
            for line in f:
                # cleaning trailing spaces and eol chars
                line = line.replace('\n', '')
                pubkey = re.sub(r'\s+$', '', line)

                # storing on memory
                self.storeKey(pubkey)

        # loading up our own key
        self.RSAKey = RSA.importKey(open(privkey, 'r').read(), passphrase)
        self.RSAKey_md5 = hashlib.md5(
            self.RSAKey.publickey().exportKey('OpenSSH')).hexdigest()
        self.cipher = PKCS1_OAEP.new(self.RSAKey)

    def storeKey(self, pubkey):
        """
        Store a public key to memory and hashes it with md5 so that we can
        identify it with less data needed
        """
        key = RSA.importKey(pubkey)
        md5 = hashlib.md5(pubkey.encode("utf-8")).hexdigest()
        self.pubkeys[md5] = key

    def encrypt(self, msg):
        """
        Encrypt a message with all keys loaded in memory
        The resultant json looks something like this:
        {
            "id_pubkey1": "encrypted message with this pubkey"
            "id_pubkey2": "encrypted message with another pubkey"
            (...)
        }
        """
        # putting the data in a dictionary with
        # (key_md5 => encrypted_message) elements
        emsg = {}
        for md5, key in self.pubkeys.items():
            cipher = PKCS1_OAEP.new(key)
            emsg[md5] = str(
                base64.b64encode(cipher.encrypt(msg.encode("utf-8"))))

        # encoding in json to easen our lives
        return json.dumps(emsg)

    def decrypt(self, emsg):
        """
        Searches for our pubkey identifier in the json received and decrypts
        the message with our privkey
        """
        emsg = json.loads(json.dumps(eval(emsg)))

        # if the message wasnt encrypted using our key, return a empty string
        if self.RSAKey_md5 not in emsg:
            return "Key not found! Your friend don't have your pubkey loaded!"

        # we only need to decrypt the msg associated with our md5
        msg = self.cipher.decrypt(base64.b64decode(eval(
            emsg[self.RSAKey_md5])))

        return msg.decode("utf-8")


class User(LineReceiver):
    """
    Handles communication with the server
    """

    def __init__(self, factory):
        self.factory = factory
        self.state = 'DISCONNECTED'
        self.RSACipher = RSACipher(PRIV_KEY, PASSPHRASE, AUTHORIZED_KEYS)

    def connectionMade(self):
        self.factory.controller.printMsg('Connected!')
        self.state = 'CONNECTED'
        self.send('[!] PASSWD ' + SERVER_PASSWD)

    def connectionLost(self, reason):
        self.factory.controller.printMsg('Disconnected! ' + repr(reason))
        self.state = 'DISCONNECTED'

    def send(self, message):
        """
        Send AES encrypted data to the server socket
        """
        # encrypting everything with local AES
        self.sendLine(EncodeAES(message))

    def broadcast(self, message):
        """
        Send a message RSA encrypted to the server so that it can broadcast it
        among its connected peers
        """
        if self.state == "DISCONNECTED":
            return

        # if message not a client warning, lets prefix it with the our nickname
        if not message.startswith('*'):
            message = '<' + self.factory.controller.nickname + '> ' + message

        self.send(self.RSACipher.encrypt(message))
        self.factory.controller.printMsg(message)

    def lineReceived(self, line):
        """
        Parses messages from the server
        """
        # first we need to decode the data
        message = DecodeAES(line)

        if self.state == 'CONNECTED':
            self.handle_CONNECTED(message)
        elif self.state == 'AUTHENTICATED':
            self.handle_AUTHENTICATED(message)

    def handle_CONNECTED(self, message):
        # checking if server has disconnected us
        if message.startswith('[!] BADPASSWD '):
            self.factory.controller.printMsg('Authentication failed.')
            return

        # checking if server has authenticated us
        if message.startswith('[!] PASSWD '):
            self.state = 'AUTHENTICATED'
            self.factory.controller.printMsg('Authenticated!')
            return

    def handle_AUTHENTICATED(self, message):
        # other server notices are just printed without decryption
        if message.startswith('[!] '):
            self.factory.controller.printMsg(message)
            return

        # if we reached this point, its not a server message
        # thus, we need to decrypt it using our private RSA key
        self.factory.controller.printMsg(self.RSACipher.decrypt(message))


class UserFactory(ClientFactory):
    """
    The twisted factory used for handling connection
    """

    def __init__(self, controller):
        self.controller = controller

    def buildProtocol(self, addr):
        user = User(self)
        self.controller.connection = user
        return user

    def startedConnecting(self, connector):
        self.controller.printMsg('Connecting...')

    def clientConnectionFailed(self, connector, reason):
        self.controller.printMsg('Connection failed! ' + repr(reason))


class UserInterface():
    """
    Everything related to our CLI is here
    """

    def __init__(self):
        self.walker = urwid.SimpleListWalker([])
        self.listbox = urwid.ListBox(self.walker)
        self.footer = urwid.Edit('')
        self.frame = urwid.Frame(self._wrap(self.listbox, 'body'),
                                 footer=self._wrap(self.footer, 'footer'),
                                 focus_part='footer')

    def _wrap(self, widget, attr_map):
        return urwid.AttrMap(widget, attr_map)

    def rawWrite(self, text):
        self.walker.append(urwid.Text(text))
        self.walker.set_focus(len(self.walker.contents) - 1)


class Controller(object):

    def __init__(self):
        self.logging = True
        # setting default nickname
        self.nickname = NICKNAME
        # initializing the user interface
        self.UI = UserInterface()
        # initializing twisted factory
        self.factory = UserFactory(self)
        # checking for errors and warnings
        self.check()
        self.printMsg('Welcome to lulchat! :)')

    def main(self):
        self.loop = urwid.MainLoop(self.UI.frame,
                                   None,
                                   unhandled_input=self.handleKeys,
                                   event_loop=urwid.TwistedEventLoop())
        self.loop.run()

    def check(self):
        """
        Checks the existance of the required config files
        """
        # ERRORS
        if not os.path.isfile(PRIV_KEY):
            self.shutdown('ERROR: Private key not found! [ PRIV_KEY = ' +
                          PRIV_KEY + ' ]')
        if not os.path.isfile(AUTHORIZED_KEYS):
            self.shutdown(
                'ERROR: Authorized keys file not found! [ AUTHORIZED_KEYS = ' +
                AUTHORIZED_KEYS + ' ]')
        elif os.stat(AUTHORIZED_KEYS).st_size == 0:
            self.shutdown('ERROR: authorized_keys is empty' + AUTHORIZED_KEYS +
                          ')')

        # WARNINGS
        if not LOG_FILE or not os.path.isfile(LOG_FILE):
            self.logging = False
            self.printMsg(
                'WARNING: No log file found, feature disabled! [ LOG_FILE = ' +
                LOG_FILE + ' ]')

    def printMsg(self, message):
        """
        Print messages to the user interface and log it to file
        """
        # feeding the queue that serves the interface
        self.UI.rawWrite(time.strftime('[%H:%M] ') + message)
        if hasattr(self, 'loop'):
            self.loop.draw_screen()

        # returning if logging feature is disabled
        if not self.logging:
            return

        # appending the logfile with a full timestamped message
        logfile = open(LOG_FILE, 'a+')
        logfile.write(
            time.strftime('[%d/%m/%Y] - (%H:%M:%S) >> ') + message + '\n')
        logfile.close()

    def handleKeys(self, key):
        """
        Parses the user keyboard input
        """
        if key != 'enter':
            return

        input = self.UI.footer.edit_text
        self.UI.footer.set_edit_text('')

        if not input.startswith('/'):
            # simple message (not a /command) should be simply broadcasted
            self.connection.broadcast(input)
            return

        # storing command
        argv = input.split(' ')

        # command to connect
        if argv[0] == '/connect':
            self.connector = reactor.connectTCP(HOST, PORT, self.factory)

        # disconnecting
        if argv[0] == '/disconnect':
            if hasattr(self, 'connector'):
                self.connector.disconnect()
            return

        # quit functionality
        if argv[0] == '/quit':
            if hasattr(self, 'connector'):
                self.connector.disconnect()
            self.shutdown()
            return

        # changing nick functionality
        if argv[0] == '/nick':
            if len(argv) < 2:
                return
            old_nickname = self.nickname
            self.nickname = argv[1]
            self.connection.broadcast('* ' + old_nickname +
                                      ' has changed nick to ' + self.nickname)
            return

        # /me 'emote'
        if argv[0] == '/me':
            self.connection.broadcast('* ' + self.nickname + ' ' +
                                      ' '.join(argv[1:]))
            return

        # lists all users currently connected
        if argv[0] == '/list':
            self.connection.send('[!] LIST ')
            return

    def shutdown(self, message=None):
        """
        Exit with a message
        """
        # printing custom shutdown message
        if message is not None:
            print(message)

        # killing the process
        sys.exit(0)


if __name__ == '__main__':
    Controller().main()
