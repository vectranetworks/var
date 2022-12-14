import logging
import json
import requests
import time
import xmltodict
from third_party_clients.third_party_interface import ThirdPartyInterface
from third_party_clients.cisco_ise.ise_config import ISE_APPLIANCE_IP, ISE_USERNAME, ISE_PASSWORD, CHECK_SSL, \
    PORTBOUNCE_POLICY, QUARANTAINE_POLICY, ENHANCED


def fetch_csrf(func):
    def _fetch_csrf(self, *args, **kwargs):
        if ENHANCED:
            headers = {**self.headers, **{'X-CSRF-TOKEN': 'fetch'}}
            print(f'args: {args}')
            print(f'kwargs: {kwargs}')
            result = requests.get('https://{}:9060/ers/config/ancendpoint/versioninfo'.format(
                self.url), auth=self.auth, headers=headers, verify=self.verify)
            kwargs = {'headers': {'csrf': result.headers['X-CSRF-Token']}, 'cookies': result.cookies}
            return func(**kwargs)
        else:
            return func()
    return _fetch_csrf


def request_error_handler(func):
    '''
    Decorator to handle request results and raise if not HTTP success
    :rtype: Requests.Reponse or Exception
    '''
    def request_handler(self, *args, **kwargs):
        response = func(self, *args, **kwargs)
        if response.status_code in [200, 201, 204]:
            return response
        # Handle the weird Cisco 500 error code that is actually a success
        elif response.status_code == 500:
            try:
                # Might raise an error
                r = response.json()
                # Might raise a KeyError
                if r['ERSResponse']['messages'][0]['title'] == "Radius Failure":
                    # If we're in the weird case, we consider it a success
                    response.status_code = 200
                    return response
                else:
                    raise HTTPException(response.status_code, response.content)
            except:
                raise HTTPException(response.status_code, response.content)
        else:
            raise HTTPException(response.status_code, response.content)
    return request_handler


class HTTPException(Exception):
    pass


class ISEClient(ThirdPartyInterface):

    @staticmethod
    def _generate_url_params(param_dict):
        """
        Generate url parameters based on a dict
        :param params: dict of keys to generate query params
        :rtype: dict
        """

        url_param = ''

        for k, v in param_dict.items():
            if v is not None and v != '': url_param += '{key}={value}&'.format(key=k, value=v)

        # Remove the last ampersand and return
        return url_param[:-1]

    def __init__(self, url=None):
        """
        Initialize Cisco ISE client
        :param url: FQDN or IP of ISE appliance - required
        :param user: Username to authenticate to ISR - required
        :param password: Password to authenticate to ISE - required
        :param verify: Verify SSL (default: False) - optional
        """
        self.logger = logging.getLogger()
        self.url = ISE_APPLIANCE_IP
        self.auth = (ISE_USERNAME, ISE_PASSWORD)
        self.verify = CHECK_SSL
        self.portbounce_policy = PORTBOUNCE_POLICY
        self.quarantine_policy = QUARANTAINE_POLICY
        self.headers = {
            'Accept': "application/json",
            'Content-Type': "application/json"
            }
        # Instantiate parent class
        ThirdPartyInterface.__init__ (self)

    def block_host(self, host):
        mac_addresses = set(host.mac_addresses)
        # Check if the current MAC is already known
        try:
            mac_address = self._get_mac_from_ip(host.ip)
            mac_addresses.add(mac_address)
        except HTTPException:
            pass
        # Iterate through all known MAC addresses
        for mac_address in mac_addresses:
                self._quarantaine_endpoint(mac_address)
        return mac_addresses

    def unblock_host(self, host):
        mac_addresses = host.blocked_elements.get(self.__class__.__name__, [])
        for mac_address in mac_addresses:
            self._unquarantaine_endpoint(mac_address)
        return mac_addresses
    
    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn('ISE client does not implement detection-based blocking')
        return []

    def unblock_detection(self, detection):
        # this client only implements Host-basd blocking
        return []

    def _quarantaine_endpoint(self, mac_address):
        """
        Put an endpoint in the Quarantaine policy based on its MAC address
        :param mac_address: MAC address of the endpoint to quarantain - required
        :rtype: None
        """
        # We need first to put the endpoint in a temporary policy to make the port bounce
        try:
            self._add_mac_to_policy(mac_address, self.portbounce_policy)
        except HTTPException:
            pass
        time.sleep(1)
        # Then we push the endpoint in the actual quarantaine policy
        self._add_mac_to_policy(mac_address, self.quarantine_policy)

    @request_error_handler
    @fetch_csrf
    def _unquarantaine_endpoint(self, mac_address, **kwargs):
        """
        Remove and endpoint from the Quarantaine policy based on its MAC address
        :param mac_address: MAC address of the endpoint to unquarantaine - required
        :rtype: Requests.Response
        """
        payload = {
            'OperationAdditionalData' : {
                'additionalData' : [
                    {
                        'name': 'macAddress',
                        'value': mac_address
                    },
                    {
                        'name': 'policyName',
                        'value': self.quarantine_policy
                    }
                ]
            }
        }

        return requests.put('https://{url}:9060/ers/config/ancendpoint/clear'.format(url=self.url),
                            auth=self.auth,
                            headers={**self.headers, **kwargs['headers']['csrf']} if kwargs['headers']['csrf'] else
                            self.headers,
                            json=payload, verify=self.verify,
                            cookies=kwargs['cookies'] if kwargs['cookies'] else None)

    @request_error_handler
    @fetch_csrf
    def _add_mac_to_policy(self, mac_address, policy_name, **kwargs):
        """
        Put an endpoint in a temporary policy based on its MAC address
        :param mac_address: the MAC address of the endpoint - required
        :param policy_name: name of the policy to add the endpoint to
        :rtype: Requests.Response
        """
        payload = {
            'OperationAdditionalData' : {
                'additionalData' : [
                    {
                        'name': 'macAddress',
                        'value': mac_address
                    },
                    {
                        'name': 'policyName',
                        'value': policy_name
                    }
                ]
            }
        }

        return requests.put('https://{url}:9060/ers/config/ancendpoint/apply'.format(url=self.url),
                            auth=self.auth,
                            headers={**self.headers, **kwargs['headers']['csrf']} if kwargs['headers']['csrf'] else
                            self.headers,
                            json=payload, verify=self.verify,
                            cookies=kwargs['cookies'] if kwargs['cookies'] else None)

    @fetch_csrf
    def _get_mac_from_ip(self, ip_address, **kwargs):
        """
        Get the MAC address of an endpoint base on its last IP
        :param ip_address: IP Adress to get the MAC address for
        :rtype: string
        """
        r = requests.get('https://{url}/admin/API/mnt/Session/EndPointIPAddress/{ip}'.format(url=self.url, ip=ip_address),
                         auth=self.auth, verify=False,
                         headers={**self.headers, **kwargs['headers']['csrf']} if kwargs['headers']['csrf'] else
                         self.headers,
                         cookies=kwargs['cookies'] if kwargs['cookies'] else None)
        if r.status_code not in [200, 201, 202, 203, 204]:
            raise HTTPException('No Session on ISE for IP {}'.format(ip_address))
        else:
            xml = json.loads(json.dumps(xmltodict.parse(r.text)))
            mac_address = xml['sessionParameters']['calling_station_id']
            return mac_address

