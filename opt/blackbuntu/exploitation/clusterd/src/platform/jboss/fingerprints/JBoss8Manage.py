from src.platform.jboss.interfaces import JINTERFACES
from cprint import FingerPrint


class FPrint(FingerPrint):

    def __init__(self):
        self.platform = "jboss"
        self.version = "8.0"
        self.title = JINTERFACES.MM
        self.uri = "/console/app/community.css"
        self.port = 9990
        self.hash = "8cc75d302cebed555dea0290b86cc9cc"
