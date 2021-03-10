import logging
import json
import requests
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


class FortiGate:
    def __init__(self, ipaddr, token, vdom="root", port="443", verify=False):
        self.urlbase = "https://{ipaddr}:{port}".format(ipaddr=ipaddr,port=str(port))
        self.params = {
            'access_token':token,
            'vdom':vdom
            }
        self.verify = verify
        self.logger = logging.getLogger()

    def get_firewall_address(self, specific=False, filters=False):
        """
        Get address object information from firewall

        :param specific: If provided, a specific object will be returned. If not, all objects will be returned.
        :param filters: If provided, the raw filter is appended to the API call.

        :return: Requests.Response object
        """
        params = self.params.copy()
        api_url = "{url}/api/v2/cmdb/firewall/address/".format(url=self.urlbase)
        if specific:
            api_url += specific
        elif filters:
            params.update({
                'filter':filters
            })
        return requests.get(url=api_url, params=params, verify=self.verify)
        
    def create_firewall_address(self, ip_address):
        """
        Create firewall address record

        :param address: Address record to be created
        :param data: JSON Data with which to create the address record

        :return: Requests.Response object
        """
        data = {
            'name': ip_address, 
            'type': 'iprange', 
            'start-ip': ip_address, 
            'end-ip': ip_address
            }
        return requests.post('{url}/api/v2/cmdb/firewall/address/'.format(url=self.urlbase), json=data, params=self.params, verify=False)

    def delete_firewall_address(self, address):
        """
        Delete firewall address record

        :param address: Address record to be deleted

        :return: Requests.Response object
        """
        return requests.delete(
            url='{url}/api/v2/cmdb/firewall/address/{address}'.format(url=self.urlbase, address=address),
            verify=False, 
            params=self.params
            )

    def get_address_group(self, specific=False, filters=False):
        """
        Get address group object information from firewall

        :param specific: If provided, a specific object will be returned. If not, all objects will be returned.
        :param filters: If provided, the raw filter is appended to the API call.

        :return: requests.Response object
        """
        api_url = "{url}/api/v2/cmdb/firewall/addrgrp/".format(url=self.urlbase)
        params = self.params.copy()
        if specific:
            api_url += specific
        elif filters:
            params.update({
                'filter':filters
            })
        
        return requests.get(url=api_url, params=params, verify=self.verify)


    def update_address_group(self, group_name, member_list):
        """
        Update address group with provided data

        :param group_name: Address group being updated
        :param member_list: list of IP addresses to add or remove from the group

        :return: requests.Response object
        """
        api_url = "{url}/api/v2/cmdb/firewall/addrgrp/{group}".format(url=self.urlbase, group=group_name)
        return requests.put(url=api_url, json={'member':member_list}, params=self.params, verify=self.verify)


class FortiClient(ThirdPartyInterface):
    def __init__(self):
        self.logger = logging.getLogger()
        self.internal_block_policy_name = INTERNAL_BLOCK_POLICY
        self.external_block_policy_name = EXTERNAL_BLOCK_POLICY
        try:
            self.firewalls = []
            for auth in FIREWALLS:
                self.firewalls.append(FortiGate(ipaddr=auth['IP'], port=auth.get('PORT', 443), token=auth['TOKEN'], vdom=auth.get('VDOM', 'root'), verify=auth.get('VERIFY', False)))
        except KeyError as e:
            self.logger.error('Please configure firewall instances in config.py')
            raise e
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

    def unregister_address(self, firewall, ip_address: str):
        """Register IP with FortiGate if not already registered"""
        firewall.delete_firewall_address(ip_address)

    def register_address(self, firewall, ip_address: str):
        """Register IP with FortiGate if not already registered"""
        address_obj = firewall.get_firewall_address(ip_address)
        if address_obj.status_code == 404:
            response = firewall.create_firewall_address(ip_address)
            if response.status_code == 200:
                self.logger.debug('Address {} registered with FortiGate'.format(ip_address))
            else:
                raise HTTPError(ip_address, 'Error creating address')
    
    def update_fortinet_group(self, firewall, ip_address: str, block_type: BlockType, append=True):
        """Update/Create address group based on block type"""
        group_name = self.internal_block_policy_name if block_type == BlockType.SOURCE else self.external_block_policy_name
        # get current group
        group = firewall.get_address_group(group_name)
        if group.status_code == 404:
            raise HTTPError(group, 'Error retrieving group data for group {}'.format(group_name))
        # Parse list of current members
        member_list = group.json()['results'][0]['member']
        if append:
            member_list.append({'name':ip_address})
        else:
            for member in member_list:
                if member.get('name') == ip_address:
                    member_list.remove(member)
                    break
        r = firewall.update_address_group(group_name, member_list)
        if r.status_code == 500:
            raise HTTPError('Could not update group {}'.format(group_name))
