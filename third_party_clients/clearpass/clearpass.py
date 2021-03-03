import logging
import json
import requests
from requests import HTTPError
from enum import Enum, unique, auto
from third_party_clients.third_party_interface import ThirdPartyInterface
from third_party_clients.clearpass.clearpass_config import HOSTNAME, CHECK_SSL, CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD


class ClearPassClient(ThirdPartyInterface):
    def __init__(self):
        self.logger = logging.getLogger()
        self.url = "https://" + HOSTNAME + "/api"
        self.verify = CHECK_SSL
        try:
            url_oauth = "{url}/oauth".format(url=self.url)
            params_oauth = {
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "username": USERNAME,
                "password": PASSWORD
            }
            post_oauth = requests.post(url=url_oauth, json=params_oauth, verify=self.verify)
            post_oauth.raise_for_status()
            self.logger.info("Login to ClearPass successful.")
            self.bearer = {"Authorization": "Bearer " + post_oauth.json()["access_token"]}
        except HTTPError as http_err:
            self.logger.error('Clearpass connection issue')
            raise http_err
        except Exception as err:
            self.logger.error('Clearpass connection issue')
            raise err

        # Instantiate parent class
        ThirdPartyInterface.__init__ (self)

    def block_host(self, host):
        mac_addresses = host.mac_addresses
        for mac_address in mac_addresses:
            self._patch_endpoint(mac_address, isolated=True)
            self._disconnect_session(mac_address)
            host.add_blocked_element(mac_address)
        return host

    def unblock_host(self, host):
        mac_addresses = host.mac_addresses
        for mac_address in mac_addresses:
            self._patch_endpoint(mac_address, isolated=False)
            self._disconnect_session(mac_address)
            host.add_blocked_element(mac_address)
        return host
    
    def block_detection(self, detection):
        raise NotImplementedError

    def unblock_detection(self, detection):
        raise NotImplementedError

    def _patch_endpoint(self, mac_address, isolated=False):
        patch_endpoint_url = "{url}/endpoint/mac-address/{mac_address}".format(url=self.url, mac_address=mac_address)
        params_patch_endpoint = {
            "mac_address": mac_address,
            "attributes": {
                "isolated": isolated
            }
        }
        r = requests.patch(url=patch_endpoint_url, headers=self.bearer, verify=self.verify, json=params_patch_endpoint)
        r.raise_for_status()

    def _disconnect_session(self, mac_address):
        """ 
        Disconnects host session 
        """
        disconnect_url = "{url}/session-action/disconnect/mac/{mac_address}?async=false".format(url=self.url, mac_address=mac_address)
        disconnect = requests.post(url=disconnect_url, headers=self.bearer, verify=self.verify)
        disconnect.raise_for_status()
        