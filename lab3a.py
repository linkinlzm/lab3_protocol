import playground
import random
import sys, time, os, logging, asyncio
from .myPassthrough import *

# this is the client
class MyProtocolClient(asyncio.Protocol):
    def __init__(self, name, loop):
        self.name = "abc"
        self.loop = loop
        self.transport = None
        self._deserializer = PacketType.Deserializer()
        self.task = 1

    def connection_made(self, transport):
        self.transport = transport
        requestPkt = RequestToConnect()
        requestpktB = requestPkt.__serialize__()
        print("client: RequestToConnect sent")
        self.transport.write(requestpktB)

    def data_received(self, data):
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            print(pkt)
            if isinstance(pkt, NameRequest):
                sentNamePkt = AnswerNameRequest()
                sentNamePkt.ID = pkt.ID
                sentNamePkt.name = self.name
                sentNamePktB = sentNamePkt.__serialize__()
                print("client: AnswerNameRequest sent")
                self.transport.write(sentNamePktB)
            if isinstance(pkt, Result):
                if pkt.result == True:
                    print("connect to server success")
                    self.transport.close()
                elif pkt.result == False:
                    print("connect to server Failed")
                    self.transport.close()

    def connection_lost(self, exc):
        self.transport.close()
        self.transport = None


# this is the server
class MyProtocolServer(asyncio.Protocol):
    def __init__(self):
        self.ConnectionDict = {}
        self.transport = None
        self._deserializer = PacketType.Deserializer()

    def connection_made(self, transport):
        print("Received a connection from {}".format(transport.get_extra_info("peername")))
        self.transport = transport

    def data_received(self, data):

        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, RequestToConnect):
                print(pkt.DEFINITION_IDENTIFIER)
                print("got RequestToConnect")
                NameRequestpkt = NameRequest()
                outID = random.randint(100000, 999999)
                self.ConnectionDict[outID] = ""
                NameRequestpkt.ID = outID
                NameRequestpkt.question = "What's your name"
                NameRequestpktB = NameRequestpkt.__serialize__()
                print("server: NameRequestpkt sent")
                self.transport.write(NameRequestpktB)

            if isinstance(pkt, AnswerNameRequest):
                Resultpkt = Result()
                if pkt.ID in self.ConnectionDict:
                    self.ConnectionDict[pkt.ID] = pkt.name
                    Resultpkt.result = True
                    print("server: answer from valid user")
                else:
                    Resultpkt.result = False
                    print("server: u try to hack me?")
                ResultpktB = Resultpkt.__serialize__()
                print("server: Resultpkt sent")
                self.transport.write(ResultpktB)
                self.transport.close()
    def connection_lost(self, exc):
        self.transport.close()
        self.transport = None


#

def PeepClientFactory():
    fclient = StackingProtocolFactory(lambda: PassThroughc1(), lambda: PassThroughc2())
    return fclient


def PeepServerFactory():
    fserver = StackingProtocolFactory(lambda: PassThroughs1(), lambda: PassThroughs2())
    return fserver


def basicUnitTest():
    echoArgs = {}

    args = sys.argv[1:]
    i = 0
    for arg in args:
        if arg.startswith("-"):
            k, v = arg.split("=")
            echoArgs[k] = v
        else:
            echoArgs[i] = arg
            i += 1

    if 0 not in echoArgs:
        sys.exit("1")

    fclient = StackingProtocolFactory(lambda: PassThroughc1(), lambda: PassThroughc2())
    fserver = StackingProtocolFactory(lambda: PassThroughs1(), lambda: PassThroughs2())

    lab3Connector = playground.Connector(protocolStack=(
        fclient,
        fserver))
    playground.setConnector("lab3_protocol", lab3Connector)

    mode = echoArgs[0]
    loop = asyncio.get_event_loop()
    loop.set_debug(enabled=True)

    if mode.lower() == "server":
        coro = playground.getConnector('lab3_protocol').create_playground_server(lambda: MyProtocolServer(), 101)
        server = loop.run_until_complete(coro)
        print("my Server Started at {}".format(server.sockets[0].gethostname()))
        loop.run_forever()
        loop.close()


    else:
        address = mode
        coro = playground.getConnector('lab3_protocol').create_playground_connection(
            lambda: MyProtocolClient("hello", loop),
            address, 101)
        loop.run_until_complete(coro)
        loop.run_forever()
        loop.close()


if __name__ == "__main__":
    basicUnitTest()
