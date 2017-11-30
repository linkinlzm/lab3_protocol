import playground
from .lab3a import *

myPeepConnector = playground.Connector(protocolStack=(
    PeepClientFactory(),
    PeepServerFactory()))

playground.setConnector("lab3_protocol", myPeepConnector)
playground.setConnector("my_team_lab3_protocol", myPeepConnector)
