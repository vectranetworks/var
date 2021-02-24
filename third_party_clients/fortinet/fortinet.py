import pyfortiapi
import logging
import json
from requests import HTTPError
from enum import Enum, unique, auto
from third_party_clients.third_party_interface import ThirdPartyInterface
from third_party_clients.fortinet.fortinet_config import INTERNAL_BLOCK_POLICY, EXTERNAL_BLOCK_POLICY, FIREWALLS

@unique
class BlockType(Enum):
    """Enumerated type describing the kind of block to be done
    on FortiGate. FortiGate can block source and destination
    addresses.
    """
    SOURCE = auto()
    DESTINATION = auto()

class FortiClient(ThirdPartyInterface):
    def __init__(self):
        self.logger = logging.getLogger()
        self.internal_block_policy_name = INTERNAL_BLOCK_POLICY
        self.external_block_policy_name = EXTERNAL_BLOCK_POLICY
        try:
            self.firewalls = []
            for auth in FIREWALLS:
                self.firewalls.append(pyfortiapi.FortiGate(ipaddr=auth['IP'], username=auth['USER'], password=auth['PASS'], vdom=auth.get('VDOM', 'root'))) # ADD VDOM INFO
        except KeyError as e:
            self.logger.error('Please configure firewall instances in config.py')
            raise e
        # Instantiate parent class
        ThirdPartyInterface.__init__ (self)

    def block_host(self, host):
        ip_address = host.ip
        for firewall in self.firewalls:
            self.register_address(firewall, ip_address)
            self.update_fortinet_group(firewall, ip_address=ip_address, block_type=BlockType.SOURCE)
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
        """Load in the data set"""
        raise NotImplementedError

    def unblock_detection(self, detection):
        """Load in the data set"""
        raise NotImplementedError

    def unregister_address(self, firewall, ip_address: str):
        """Register IP with FortiGate if not already registered"""
        address = firewall.delete_firewall_address(ip_address)
        return address

    def register_address(self, firewall, ip_address: str):
        """Unregister IP with FortiGate if not already registered"""
        address = firewall.get_firewall_address(ip_address)
        if type(address) == int:
            if address == 404:
                data = json.dumps(
                    {'name': ip_address, 'type': 'iprange', 'start-ip': ip_address, 'end-ip': ip_address})
                firewall.create_firewall_address(ip_address, data)
                address = firewall.get_firewall_address(ip_address)[0]
                self.logger.debug('Address {} registered with FortiGate'.format(address['name']))
            else:
                raise HTTPError(address, 'Error retrieving address data')
    
    def update_fortinet_group(self, firewall, ip_address: str, block_type: BlockType, append=True):
        """Update/Create address group based on block type"""
        group_name = self.internal_block_policy_name if BlockType.SOURCE else self.external_block_policy_name
        group = firewall.get_address_group(group_name)
        if type(group) == int:
            raise HTTPError(group, 'Error retrieving group data for group {}'.format(group_name))
        else:
            member_list = group[0]['member']
            if append:
                member_list.append({'name':ip_address})
            else:
                for member in member_list:
                    if member.get('name') == ip_address:
                        member_list.remove(member)
                        break
            data = json.dumps({'member': member_list})
            firewall.update_address_group(group_name, data)

        return firewall.get_address_group(group_name)[0]
        