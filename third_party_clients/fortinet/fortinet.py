import logging
import json
import requests
from requests import HTTPError
from enum import Enum, unique, auto
from VectraAutomatedResponse.vectra_active_enforcement import HTTPException
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


def request_error_handler(func):
    def request_handler(self, *args, **kwargs):
        response = func(self, *args, **kwargs)
        if response.status_code in [200, 201, 204]:
            return response
        else:
            raise HTTPException(response)
    return request_handler


class FortiGate:
    def __init__(self, ipaddr, username, password, vdom="root", port="443", verify=False):
        self.ipaddr = ipaddr
        self.username = username
        self.password = password
        self.port = port
        self.verify = verify
        self.urlbase = "https://{ipaddr}:{port}".format(ipaddr=self.ipaddr,port=self.port)
        self.vdom = vdom
        self.session = requests.session()
        self.logger = logging.getLogger()
        # Login
        self.session.post(
            url=self.urlbase + '/logincheck',
            data='username={username}&secretkey={password}'.format(
                username=self.username,
                password=self.password),
            verify=self.verify,
            )
        # Get CSRF token from cookies, add to headers
        for cookie in self.session.cookies:
            if cookie.name == 'ccsrftoken':
                csrftoken = cookie.value[1:-1]  # strip quotes
                self.session.headers.update({'X-CSRFTOKEN': csrftoken})
        # Check whether login was successful
        login_check = self.session.get(self.urlbase + "/api/v2/cmdb/system/vdom")
        login_check.raise_for_status()

    def __del__(self):
        self.session.get(url=self.urlbase +'/logout', verify=self.verify)
        self.logger.info("Session logged out.")

    # API Interaction Methods
    def get(self, url):
        """
        Perform GET operation on provided URL

        :param url: Target of GET operation

        :return: Request result if successful (type list), HTTP status code otherwise (type int)
        """
        session = self.login()
        request = session.get(url, verify=False, timeout=self.timeout, params='vdom='+self.vdom)
        self.logout(session)
        if request.status_code == 200:
            return request.json()['results']
        else:
            return request.status_code

    def put(self, url, data):
        """
        Perform PUT operation on provided URL

        :param url: Target of PUT operation
        :param data: JSON data. MUST be a correctly formatted string. e.g. "{'key': 'value'}"

        :return: HTTP status code returned from PUT operation
        """
        session = self.login()
        result = session.put(url, data=data, verify=False, timeout=self.timeout, params='vdom='+self.vdom).status_code
        self.logout(session)
        return result

    def post(self, url, data):
        """
        Perform POST operation on provided URL

        :param url: Target of POST operation
        :param data: JSON data. MUST be a correctly formatted string. e.g. "{'key': 'value'}"

        :return: HTTP status code returned from POST operation
        """
        session = self.login()
        result = session.post(url, data=data, verify=False, timeout=self.timeout, params='vdom='+self.vdom).status_code
        self.logout(session)
        return result

    def delete(self, url):
        """
        Perform DELETE operation on provided URL

        :param url: Target of DELETE operation

        :return: HTTP status code returned from DELETE operation
        """
        session = self.login()
        result = session.delete(url, verify=False, timeout=self.timeout, params='vdom='+self.vdom).status_code
        self.logout(session)
        return result

    @request_error_handler
    def get_firewall_address(self, specific=False, filters=False):
        """
        Get address object information from firewall

        :param specific: If provided, a specific object will be returned. If not, all objects will be returned.
        :param filters: If provided, the raw filter is appended to the API call.

        :return: Requests.Response object
        """
        api_url = "/api/v2/cmdb/firewall/address/"
        if specific:
            api_url += specific
        elif filters:
            api_url += "?filter=" + filters
                
        return self.session.get(self.urlbase + api_url, verify=self.verify, params='vdom='+self.vdom)
        
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
        # TODO what happens is already exists
        exists = self.session.get('{url}/api/v2/cmdb/firewall/address/{ip_address}'.format(url=self.urlbase, addreip_addressss=ip_address), data=data, verify=False, params='vdom='+self.vdom)
        return self.session.post('{url}/api/v2/cmdb/firewall/address/'.format(url=self.urlbase), json=data, verify=False, params='vdom='+self.vdom)

    def delete_firewall_address(self, address):
        """
        Delete firewall address record

        :param address: Address record to be deleted

        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/address/" + address
        result = self.delete(api_url)
        return result
    
    def update_firewall_address(self, address, data):
        """
        Update firewall address record with provided data

        :param address: Address record being updated
        :param data: JSON Data with which to upate the address record

        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/address/" + requests.utils.quote(address, safe='')
        # Check whether target object exists
        if not self.does_exist(api_url):
            logging.error('Requested address "{address}" does not exist in Firewall config.'.format(address=address))
            return 404
        result = self.put(api_url, data)
        return result

    # Address Group Methods
    def get_address_group(self, specific=False, filters=False):
        """
        Get address group object information from firewall

        :param specific: If provided, a specific object will be returned. If not, all objects will be returned.
        :param filters: If provided, the raw filter is appended to the API call.

        :return: JSON data for all objects in scope of request, nested in a list.
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/addrgrp/"
        if specific:
            api_url += specific
        elif filters:
            api_url += "?filter=" + filters
        results = self.get(api_url)
        return results

    def create_address_group(self, group_name, data):
        """
        Create address group

        :param group_name: Address group to be created
        :param data: JSON Data with which to create the address group

        :return: HTTP Status Code.
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/addrgrp/"
        if self.does_exist(api_url + group_name):
            return 424
        result = self.post(api_url, data)
        return result


    def update_address_group(self, group_name, data):
        """
        Update address group with provided data

        :param group_name: Address group being updated
        :param data: JSON Data with which to upate the address group

        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/addrgrp/" + group_name
        # Check whether target object already exists
        if not self.does_exist(api_url):
            logging.error('Requested address group "{group_name}" does not exist in Firewall config.'.format(
                group_name=group_name))
            return 404
        result = self.put(api_url, data)
        return result

    def delete_address_group(self, group_name):
        """
        Delete firewall address group

        :param group_name: Address group to be deleted

        :return: HTTP Status Code
        """
        api_url = self.urlbase + "api/v2/cmdb/firewall/addrgrp/" + group_name
        result = self.delete(api_url)
        return result

class FortiClient(ThirdPartyInterface):
    def __init__(self):
        self.logger = logging.getLogger()
        self.internal_block_policy_name = INTERNAL_BLOCK_POLICY
        self.external_block_policy_name = EXTERNAL_BLOCK_POLICY
        try:
            self.firewalls = []
            for auth in FIREWALLS:
                self.firewalls.append(FortiGate(ipaddr=auth['IP'], username=auth['USER'], password=auth['PASS'], vdom=auth.get('VDOM', 'root'))) # ADD VDOM INFO
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
        