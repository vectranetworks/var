import logging
import uuid
from third_party_clients.third_party_interface import ThirdPartyInterface


class TestClient(ThirdPartyInterface):
    def __init__(self):
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def block_host(self, host):
        id = uuid.uuid4()
        return [id]

    def unblock_host(self, host):
        return host.blocked_elements.get(self.__class__.__name__)

    def groom_host(self, host) -> dict:
        return {'block': [], 'unblock': []}
    
    def block_detection(self, detection):
        id = uuid.uuid4()
        return [id]

    def unblock_detection(self, detection):
        return detection.blocked_elements.get(self.__class__.__name__)

