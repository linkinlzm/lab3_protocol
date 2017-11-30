from .lab3a import *


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
