import logging
import json
import requests
import base64
import time
from cachetools import cached, TTLCache
from third_party_clients.third_party_interface import ThirdPartyInterface
from third_party_clients.bitdefender.bitdefender_config import HOSTNAME, CHECK_SSL, API_KEY, BLOCK_MULTIPLE


class BitdefenderClient(ThirdPartyInterface):
    def __init__(self):
        self.logger = logging.getLogger()
        self.apiKey = API_KEY
        self.url = "https://" + HOSTNAME + "/api/v1.0/jsonrpc"
        self.verify = CHECK_SSL
        self.block_multiple = BLOCK_MULTIPLE
        login_string = self.apiKey + ":"
        encoded_bytes = base64.b64encode(login_string.encode())
        encoded_user_pass_sequence = str(encoded_bytes, 'utf-8')
        self.authorization_header = {'Authorization': 'Basic ' + encoded_user_pass_sequence,
                                     'Content-Type': 'application/json'}
        self.company_id = self._get_company_id()
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def _get_company_id(self):
        body = {
            "params": {},
            "jsonrpc": "2.0",
            "method": "getCompanyDetails",
            "id": "0df7568c-59c1-48e0-a31b-18d83e6d9810"
        }
        res = requests.post(url=self.url + '/companies', headers=self.authorization_header, data=json.dumps(body),
                            verify=self.verify)
        return res.json()['result']['id']

    def block_host(self, host):
        endpoint_ids = self._get_endpoint_id(host)
        if len(endpoint_ids) > 1 and self.block_multiple:
            for endpoint in endpoint_ids:
                if endpoint:
                    self.logger.info('Quarantining endpoint:{}'.format(endpoint))
                    result = self._isolate_endpoint(endpoint)
                    if not result:
                        self.logger.info('Unable to Quarantine endpoint:{}'.format(endpoint))
                    elif 'error' in result.keys():
                        self.logger.info('Unable to quarantined endpoint:{} with response:{}'.format(endpoint, result))
                    else:
                        self.logger.debug('Quarantined endpoint:{} with response:{}'.format(endpoint, result))
        elif len(endpoint_ids) == 1:
            self.logger.info('Quarantining endpoint:{}'.format(endpoint_ids[0]))
            result = self._isolate_endpoint(endpoint_ids[0])
            if not result:
                self.logger.info('Unable to Quarantine endpoint:{}'.format(endpoint_ids[0]))
            elif 'error' in result.keys():
                self.logger.debug('Unable to quarantined endpoint:{} with response:{}'.format(endpoint_ids, result))
            else:
                self.logger.debug('Quarantined endpoint:{} with response:{}'.format(endpoint_ids[0], result))
        else:
            self.logger.info('Not configured to block multiple endpoints or no endpoint found for host{}. {}'.format(
                host.name, endpoint_ids))
        return endpoint_ids

    def unblock_host(self, host):
        endpoint_ids = host.blocked_elements.get(self.__class__.__name__, [])
        for endpoint_id in endpoint_ids:
            if endpoint_id:
                self.logger.info('Unquarantining endpoint:{},{}'.format(host.name, endpoint_id))
                result = self._restore_endpoint(endpoint_id)
                if not result:
                    self.logger.info('Unable to unquarantine endpoint:{},{}'.format(host.name, endpoint_id))
                elif 'error' in result.keys():
                    self.logger.info('Unable to unquarantined endpoint:{} with response:{}'.format(endpoint_id, result))
            else:
                self.logger.info('No proper endpoint id supplied:{}'.format(endpoint_ids))
        return endpoint_ids

    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn('Bitdefender client does not implement detection-based blocking')
        return []

    def unblock_detection(self, detection):
        # this client only implements Host-basd blocking
        return []

    def _get_endpoint_id(self, host):
        endpoint_ids = []
        # Try getEndpointsList
        # https://www.bitdefender.com/business/support/en/77209-128483-getendpointslist.html
        for mac_address in host.mac_addresses:
            request = {
                "params": {
                    "parentId": self.company_id,
                    "filters": {
                        "details": {
                            "macs": [mac_address.replace(':', '')]
                          },
                        "depth": {
                            "allItemsRecursively": True
                        },
                        "type": {
                            "computers": True,
                            "virtualMachines": True
                        }
                      }
                    },
                "jsonrpc": "2.0", "method": "getEndpointsList", "id": "301f7b05-ec02-481b-9ed6-c07b97de2b7b"
            }
            result = requests.post(
                "{url}/network".format(url=self.url),
                data=json.dumps(request),
                verify=self.verify,
                headers=self.authorization_header)
            json_response = result.json()
            if json_response["result"].get('items'):
                endpoint_ids += [i['id'] for i in json_response["result"]["items"]]
            else:
                # Try getnetworkInventoryItems
                # https://www.bitdefender.com/business/support/en/77209-128494-getnetworkinventoryitems.html
                request = {
                    "params": {
                        "parentId": self.company_id,
                        "page": 1,
                        "perPage": 1,
                        "filters": {
                            "details": {"macs": [mac_address.replace(':', '')]},
                            "type": {
                                "computers": True,
                                "virtualMachines": True
                            },
                            "depth": {
                                "allItemsRecursively": True
                            }
                        },
                        "options": {
                            "companies": {
                                "returnAllProducts": True
                            }
                        }
                    },
                    "jsonrpc": "2.0",
                    "method": "getNetworkInventoryItems",
                    "id": "301f7b05-ec02-481b-9ed6-c07b97de2b7b"
                }
                result = requests.post(
                    "{url}/network".format(url=self.url),
                    data=json.dumps(request),
                    verify=self.verify,
                    headers=self.authorization_header)
                json_response = result.json()
                self.logger.debug('json_response:{}'.format(json_response))
                if json_response["result"].get('items'):
                    if len(json_response['result'].get('items')) == 1:
                        endpoint_ids += [i['id'] for i in json_response["result"]["items"]]
                else:
                    self.logger.info('Endpoint not found via MAC: {}'.format(mac_address))
        if endpoint_ids:
            return endpoint_ids
        else:
            self.logger.info('Endpoint not found via MAC address list: {}'.format(host.mac_addresses))
            self.logger.info('Retrieving all endpoints from API for comparison with IP:{}'.format(host.ip))
            endpoint_dict = self._get_all_endpoints()
            endpoint_ids += [i['id'] for i in endpoint_dict.get('inventory', []) if i['ip'] == host.ip]
            endpoint_ids += [i['id'] for i in endpoint_dict.get('endpoints', []) if i['ip'] == host.ip]
            self.logger.debug('List being returned: {}'.format(endpoint_ids))
            return endpoint_ids

    @cached(cache=TTLCache(maxsize=4480000, ttl=1200))
    def _get_all_endpoints(self):
        endpoints = []
        inventory = []
        # Try getEndpointsList
        # https://www.bitdefender.com/business/support/en/77209-128483-getendpointslist.html
        # Initialize looping vars
        page = 1
        page_count = 2
        while page < page_count:
            request = {"params": {"perPage": 100, "page": page, "parentId": self.company_id, "filters": {
                "depth": {
                    "allItemsRecursively": True
                },
                "type": {
                    "computers": True,
                    "virtualMachines": True
                }
            }},
                       "jsonrpc": "2.0", "method": "getEndpointsList", "id": "301f7b05-ec02-481b-9ed6-c07b97de2b7b"}
            self.logger.debug('{}'.format(request))
            result = requests.post(
                "{url}/network".format(url=self.url),
                data=json.dumps(request),
                verify=self.verify,
                headers=self.authorization_header)
            json_response = result.json()
            page += 1
            if json_response['result']:
                page_count = json_response['result']['pagesCount']
                if json_response["result"].get('items'):
                    endpoints += [{'id': i['id'], 'ip': i['ip']} for i in json_response["result"].get('items', [])]

        # Initialize looping vars
        page = 1
        page_count = 2
        # Try getnetworkInventoryItems
        # https://www.bitdefender.com/business/support/en/77209-128494-getnetworkinventoryitems.html
        while page < page_count:
            request = {
                "params": {
                    "parentId": self.company_id,
                    "page": page,
                    "perPage": 100,
                    "filters": {
                        "type": {
                            "computers": True,
                            "virtualMachines": True
                        },
                        "depth": {
                            "allItemsRecursively": True
                        }
                    },
                    "options": {
                        "companies": {
                            "returnAllProducts": True
                        }
                    }
                },
                "jsonrpc": "2.0",
                "method": "getNetworkInventoryItems",
                "id": "301f7b05-ec02-481b-9ed6-c07b97de2b7b"
            }
            self.logger.debug('{}'.format(request))
            result = requests.post(
                "{url}/network".format(url=self.url),
                data=json.dumps(request),
                verify=self.verify,
                headers=self.authorization_header)
            json_response = result.json()
            page += 1
            if json_response['result']:
                page_count = json_response['result']['pagesCount']
                if json_response["result"].get('items'):
                    inventory += [{'id': i['id'], 'ip': i['details']['ip']} for i in
                                  json_response["result"].get('items')]
        with open('bitdefender.json', 'w') as fp:
            fp.write(json.dumps({'endpoints': endpoints, 'inventory': inventory}))
        return {'endpoints': endpoints, 'inventory': inventory}

    def _isolate_endpoint(self, endpoint_id):
        request = {
            "id": "0df7568c-59c1-48e0-a31b-18d83e6d9810",
            "jsonrpc": "2.0",
            "method": "createIsolateEndpointTask",
            "params": {
                "endpointId": endpoint_id
            }
        }
        # self.logger.debug('\nBody:{}\n'.format(request))
        # self.logger.debug('Headers:{}\n'.format(self.authorization_header))
        result = requests.post(
            "{url}/incidents".format(url=self.url),
            json=request,
            verify=self.verify,
            headers=self.authorization_header)

        json_response = result.json()
        return json_response

    def _restore_endpoint(self, endpoint_id):
        request = {
            "id": "0df7568c-59c1-48e0-a31b-18d83e6d9810",
            "jsonrpc": "2.0",
            "method": "createRestoreEndpointFromIsolationTask",
            "params": {
                "endpointId": endpoint_id
            }
        }

        result = requests.post(
            "{url}/incidents".format(url=self.url),
            json=request,
            verify=self.verify,
            headers=self.authorization_header)

        json_response = result.json()
        return json_response

