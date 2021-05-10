import logging
import io
import requests
from requests import HTTPError
from enum import Enum, unique, auto
from third_party_clients.third_party_interface import ThirdPartyInterface
from third_party_clients.pan.pan_config import PAN_APPLIANCE_IP, PAN_API_KEY, INTERNAL_BLOCK_POLICY, EXTERNAL_BLOCK_POLICY, VERIFY_SSL

@unique
class BlockType(Enum):
    """Enumerated type describing the kind of block to be done
    on FortiGate. FortiGate can block source and destination
    addresses.
    """
    SOURCE = auto()
    DESTINATION = auto()


class PANClient(ThirdPartyInterface):
    def __init__(self):
        self.logger = logging.getLogger()
        self.base_url = PAN_APPLIANCE_IP
        self.api_key = PAN_API_KEY
        self.verify = VERIFY_SSL
        self.internal_block_policy_name = INTERNAL_BLOCK_POLICY
        self.external_block_policy_name = EXTERNAL_BLOCK_POLICY
        # Instantiate parent class
        ThirdPartyInterface.__init__ (self)

    def block_host(self, host):
        ip_address = host.ip
        for firewall in self.firewalls:
            self.register_address(firewall, ip_address)
            self.update_fortinet_group(firewall, ip_address=ip_address, block_type=BlockType.SOURCE, append=True)
        host.add_blocked_element(ip_address)
        return host

    def unblock_host(self, host):
        ip_addresses = host.blocked_elements
        if len(ip_addresses) < 1:
            self.logger.error('No IP address found for host {}'.format(host.name))
        for ip_address in ip_addresses:
            for firewall in self.firewalls:
                self.update_fortinet_group(firewall, ip_address=ip_address, block_type=BlockType.SOURCE, append=False)
                self.unregister_address(firewall, ip_address)
        host.blocked_elements = []
        return host
    
    def block_detection(self, detection):
        ip_addresses = detection.dst_ips
        for firewall in self.firewalls:
            for ip in ip_addresses:
                self.register_address(firewall, ip)
                self.update_fortinet_group(firewall, ip_address=ip, block_type=BlockType.DESTINATION, append=True)
                detection.add_blocked_element(ip)
        return detection

    def unblock_detection(self, detection):
        ip_addresses = detection.blocked_elements
        if len(ip_addresses) < 1:
            self.logger.error('No IP address found for Detection ID {}'.format(detection.id))
        for ip_address in ip_addresses:
            for firewall in self.firewalls:
                self.update_fortinet_group(firewall, ip_address=ip_address, block_type=BlockType.DESTINATION, append=False)
                self.unregister_address(firewall, ip_address)
        detection.blocked_elements = []
        return detection

    def quarantaine_endpoint(self, ip_address, block_type):
        """
        Add an endpoint to the quarantaine group based on its IP address
        :param ip_address: IP address of the endpoint to quarantain - required
        :rtype: requests.Reponse
        """
        target_dynamic_list = self.internal_block_policy_name if block_type == BlockType.SOURCE else self.external_block_policy_name
        payload = io.StringIO('<uid-message><version>1.0</version><type>update</type><payload><register>\
            <entry ip="{ip}"><tag><member>{member}</member></tag></entry></register></payload></uid-message>'\
            .format(ip=ip_address, member=target_dynamic_list))
    
        return requests.post('{url}/api/?type=user-id&action=set&key={api_key}'.format(url=self.url, api_key=self.api_key), files={'file':payload}, verify=False)

    def unquarantaine_endpoint(self, ip_address, block_type):
        """
        Add an endpoint to the quarantaine group based on its IP address
        :param ip_address: IP address of the endpoint to quarantain - required
        :rtype: requests.Reponse
        """
        target_dynamic_list = self.internal_block_policy_name if block_type == BlockType.SOURCE else self.external_block_policy_name
        payload = io.StringIO('<uid-message><version>1.0</version><type>update</type><payload><unregister>\
            <entry ip="{ip}"><tag><member>{member}</member></tag></entry></unregister></payload></uid-message>'\
            .format(ip=ip_address, member=target_dynamic_list))
    
        return requests.post('{url}/api/?type=user-id&action=set&key={api_key}'.format(url=self.url, api_key=self.api_key), files={'file':payload}, verify=False)
