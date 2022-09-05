import base64
import hashlib

from Crypto.Cipher import AES
from twisted.internet import reactor
from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import LineReceiver

#########################################################################
# ****************************** GLOBALS ****************************** #
#########################################################################
# * SERVER INFORMATION:                                                 #
#   - The port this server will listen to.                              #
PORT = 8888
#   - The md5 hash of the password.                                     #
#     e.g. hashlib.md5(b"thisisapassword")                              #
SERVER_PASSWD = '15c4683193f210ca9c640af9241e8c18'
#   - The unsafe AES key shared with the clients to encrypt everythig.  #
AES_KEY = 'aaaaaaaaaaaaaaaa'.encode("utf-8")
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


class User(LineReceiver):
    """
    The request handler class for our server.
    """

    def __init__(self, factory, addr):
        self.addr = format(addr)
        self.factory = factory
        self.state = 'CONNECTED'

    def connectionMade(self):
        self.broadcast('[!] NOTICE: NEW connection from ' + self.addr)
        self.factory.users.append(self)

    def connectionLost(self, reason):
        self.broadcast('[!] NOTICE: DROPPED connection from ' + self.addr)
        self.factory.users.remove(self)

    def send(self, message):
        """
        Sends AES encrypted data to the client socket
        """
        # encrypting everything with AES first
        self.sendLine(EncodeAES(message))

    def broadcast(self, message):
        """
        This method will relay a message to all authenticated clients
        """
        print('Broadcasting: ' + message)

        for protocol in self.factory.users:
            # if client is not authenticated, we must skip him
            if protocol.state != 'AUTHENTICATED':
                continue

            # sending to all *other* clients
            if protocol != self:
                protocol.send(message)

    def lineReceived(self, line):
        """
        Parses a message from the client, wether it needs any server
        function other than broadcast or not
        """

        # first we need to decode the data
        message = DecodeAES(line)

        if self.state == 'CONNECTED':
            self.handle_CONNECTED(message)
        elif self.state == 'AUTHENTICATED':
            self.handle_AUTHENTICATED(message)

    def handle_CONNECTED(self, message):
        """
        Handling messages of a CONNECTED client
        """
        # we're receiving the server password from the client
        if message.startswith('[!] PASSWD '):
            # hash the received passwd and compare it to the one we have
            if hashlib.md5(message.split('[!] PASSWD ')[1].encode(
                    "utf-8")).hexdigest() != SERVER_PASSWD:
                # letting the client knows he's still not authenticated
                self.broadcast('[!] NOTICE: REJECTED connection from ' +
                               format(self.addr))
                self.send('[!] BADPASSWD ')
                return

            # announcing
            self.state = 'AUTHENTICATED'
            self.send('[!] PASSWD ')
            self.broadcast('[!] NOTICE: ACCEPTED connection from ' +
                           format(self.addr))
            return

    def handle_AUTHENTICATED(self, message):
        """
        Handling messages of a AUTHENTICATED client
        """
        # client wants to know who is connected to the server
        if message.startswith('[!] LIST '):
            for protocol in self.factory.users:
                if protocol != self:
                    self.send('[!] ' + protocol.addr)
            return

        # if we reached this point, its just another simple broadcast
        self.broadcast(message)


class UserFactory(ServerFactory):
    """
    The twisted factory used for handling each connection received
    """

    def __init__(self):
        # keeping track of clients connected
        self.users = []

    def buildProtocol(self, addr):
        return User(self, addr)


def main():
    # initializing twisted server
    reactor.listenTCP(PORT, UserFactory())
    reactor.run()


if __name__ == '__main__':
    main()
