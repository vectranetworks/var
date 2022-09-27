import logging
import json
import requests
import base64
from requests import HTTPError
from enum import Enum, unique, auto
from third_party_clients.third_party_interface import ThirdPartyInterface
from third_party_clients.bitdefender.bitdefender_config import HOSTNAME, CHECK_SSL, API_KEY


class BitdefenderClient(ThirdPartyInterface):
    def __init__(self):
        self.logger = logging.getLogger()
        self.apiKey = API_KEY

        self.url = "https://" + HOSTNAME + "/api/v1.0/jsonrpc"
        self.verify = CHECK_SSL

        loginString = self.apiKey + ":"
        encodedBytes = base64.b64encode(loginString.encode())
        encodedUserPassSequence = str(encodedBytes,'utf-8')
        self.authorizationHeader = "Basic " + encodedUserPassSequence

        # Instantiate parent class
        ThirdPartyInterface.__init__ (self)

    def block_host(self, host):
        mac_addresses = host.mac_addresses
        for mac_address in mac_addresses:
            endpointId = self._get_endpoint_id(mac_address)
            self._isolate_endpoint(endpointId)
        return mac_addresses

    def unblock_host(self, host):
        mac_addresses = host.blocked_elements.get(self.__class__.__name__, [])
        for mac_address in mac_addresses:
            endpointId = self._get_endpoint_id(mac_address)
            self._restore_endpoint(endpointId)
        return mac_addresses

    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn('Bitdefender client does not implement detection-based blocking')
        return []

    def unblock_detection(self, detection):
        # this client only implements Host-basd blocking
        return []

    def _get_endpoint_id(self, mac_address):

        request = '{"params": {"filters":{"details":{"macs":['+mac_address+']}}},"jsonrpc": "2.0","method": "getEndpointsList","id": "301f7b05-ec02-481b-9ed6-c07b97de2b7b"}'

        result = requests.post(
            "{url}/network".format(url=self.url),
            data=request,
            verify=self.verify,
            headers = {
                "Content-Type": "application/json",
                "Authorization": self.authorizationHeader
            })
        jsonResponse = result.json()
        return jsonResponse["result"]["items"]["id"]

    def _isolate_endpoint(self, endpointId):
        request = '{"params": {"endpointId" : '+endpointId+'},"jsonrpc": "2.0","method": "createIsolateEndpointTask","id": "0df7568c-59c1-48e0-a31b-18d83e6d9810"}'

        result = requests.post(
            "{url}/incidents".format(url=self.url),
            data=request,
            verify=self.verify,
            headers = {
                "Content-Type": "application/json",
                "Authorization": self.authorizationHeader
            })

        jsonResponse = result.json()
        return jsonResponse["result"]

    def _restore_endpoint(self, endpointId):
        request = '{"params": {"endpointId" : '+endpointId+'},"jsonrpc": "2.0","method": "createRestoreEndpointFromIsolationTask","id": "0df7568c-59c1-48e0-a31b-18d83e6d9810"}'

        result = requests.post(
            "{url}/incidents".format(url=self.url),
            data=request,
            verify=self.verify,
            headers = {
                "Content-Type": "application/json",
                "Authorization": self.authorizationHeader
                })

            jsonResponse = result.json()
            return jsonResponse["result"]
