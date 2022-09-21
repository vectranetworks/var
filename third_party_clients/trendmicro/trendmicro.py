import base64
import jwt
import hashlib
import time
import json
import urllib.parse
import logging
import io
import requests
from requests import HTTPError
from enum import Enum, unique, auto
from third_party_clients.third_party_interface import ThirdPartyInterface
from third_party_clients.trendmicro.trendmicro_config import BASE_URL, APPLICATION_ID, API_KEY, API_PATH


class TrendMicroClient(ThirdPartyInterface):
    def __init__(self):
        self.logger = logging.getLogger()
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def block_host(self, host):
        mac_addresses = host.mac_addresses
        ip_address = host.ip
        if len(mac_addresses) < 1:
            # No MAC Address found, block IP
            self._patch_endpoint(ip_address=ip_address,
                                 act="cmd_isolate_agent")
            return [ip_address]
        else:
            for mac_address in mac_addresses:
                self._patch_endpoint(
                    mac_address=mac_address, act="cmd_isolate_agent")
            return mac_addresses

    def unblock_host(self, host):
        mac_addresses = host.mac_addresses
        ip_address = host.ip
        if len(mac_addresses) < 1:
            # No MAC Address found, block IP
            self._patch_endpoint(ip_address=ip_address,
                                 act="cmd_restore_isolated_agent")
            return [ip_address]
        else:
            for mac_address in mac_addresses:
                self._patch_endpoint(
                    mac_address=mac_address, act="cmd_restore_isolated_agent")
            return mac_addresses

    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn(
            'Trend Micro client does not implement detection-based blocking')
        return []

    def unblock_detection(self, detection):
        # this client only implements Host-basd blocking
        self.logger.warn(
            'Trend Micro client does not implement detection-based blocking')
        return []

    def _patch_endpoint(self, act, mac_address='', ip_address=''):
        payload = {
            "act": act,
            "allow_multiple_match": False
        }

        if ip_address:
            payload["ip_address"] = ip_address
        else:
            payload["mac_address"] = mac_address

        useRequestBody = json.dumps(payload)

        jwt_token = self.create_jwt_token(useRequestBody)

        headers = {'Authorization': 'Bearer ' + jwt_token,
                   'Content-Type': 'application/json;charset=utf-8'}

        r = requests.post(BASE_URL + API_PATH, headers=headers,
                          data=useRequestBody, verify=False)
        r.raise_for_status()

    @staticmethod
    def create_checksum(http_method, raw_url, headers, request_body):
        string_to_hash = http_method.upper() + '|' + raw_url.lower() + \
            '|' + headers + '|' + request_body
        base64_string = base64.b64encode(hashlib.sha256(
            str.encode(string_to_hash)).digest()).decode('utf-8')
        return base64_string

    def create_jwt_token(self, request_body):
        payload = {'appid': APPLICATION_ID,
                   'iat': time.time(),
                   'version': 'V1',
                   'checksum': self.create_checksum('POST', API_PATH, "", request_body)}
        # token = jwt.encode(payload, API_KEY, algorithm='HS256').decode('utf-8')
        token = jwt.encode(payload, API_KEY, algorithm='HS256')
        return token
