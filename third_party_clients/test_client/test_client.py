import logging
from third_party_clients.third_party_interface import ThirdPartyInterface


class TestClient(ThirdPartyInterface):
    def __init__(self):
        # Instantiate parent class
        ThirdPartyInterface.__init__ (self)

    def block_host(self, host):
        return host

    def unblock_host(self, host):
        return host
    
    def block_detection(self, detection):
        return detection

    def unblock_detection(self, detection):
        return detection

