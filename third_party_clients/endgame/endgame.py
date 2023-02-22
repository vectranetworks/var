import logging
import io
import requests
from requests import HTTPError
from enum import Enum, unique, auto
from third_party_clients.third_party_interface import ThirdPartyInterface
from third_party_clients.endgame.endgame_config import ENDGAME_URL, ENDGAME_API_TOKEN, VERIFY_SSL

@unique
class BlockType(Enum):
    """Enumerated type describing the kind of block to be done
    on FortiGate. FortiGate can block source and destination
    addresses.
    """
    SOURCE = auto()
    DESTINATION = auto()


class EndgameClient(ThirdPartyInterface):
    def __init__(self):
        self.logger = logging.getLogger()
        self.url = '{url}/api/v1'.format(url=ENDGAME_URL)
        self.headers = {
            'Authorization': "JWT " + ENDGAME_API_TOKEN.strip(),
            'Content-Type': "application/json",
            'Cache-Control': "no-cache"
        }
        self.verify = VERIFY_SSL

    def block_host(self, host):
        ip_address = host.ip
        for firewall in self.firewalls:
            self.register_address(firewall, ip_address)
            self.update_fortinet_group(firewall, ip_address=ip_address, block_type=BlockType.SOURCE, append=True)
        return [ip_address]

    def unblock_host(self, host):
        ip_addresses = host.blocked_elements.get(self.__class__.__name__, [])
        if len(ip_addresses) < 1:
            self.logger.error('No IP address found for host {}'.format(host.name))
        for ip_address in ip_addresses:
            for firewall in self.firewalls:
                self.update_fortinet_group(firewall, ip_address=ip_address, block_type=BlockType.SOURCE, append=False)
                self.unregister_address(firewall, ip_address)
        return ip_addresses

    def groom_host(self, host) -> dict:
        self.logger.warning('Endgame client does not implement host grooming')
        return []

    def block_detection(self, detection):
        ip_addresses = detection.dst_ips
        for firewall in self.firewalls:
            for ip in ip_addresses:
                self.register_address(firewall, ip)
                self.update_fortinet_group(firewall, ip_address=ip, block_type=BlockType.DESTINATION, append=True)
        return ip_addresses

    def unblock_detection(self, detection):
        ip_addresses = detection.blocked_elements.get(self.__class__.__name__, [])
        if len(ip_addresses) < 1:
            self.logger.error('No IP address found for Detection ID {}'.format(detection.id))
        for ip_address in ip_addresses:
            for firewall in self.firewalls:
                self.update_fortinet_group(firewall, ip_address=ip_address, block_type=BlockType.DESTINATION, append=False)
                self.unregister_address(firewall, ip_address)
        return ip_addresses