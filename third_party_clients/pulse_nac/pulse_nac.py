import logging
import requests
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os.path
import base64
import urllib3
import uuid
import json
from third_party_clients.third_party_interface import ThirdPartyInterface
from third_party_clients.pulse_nac.pulse_nac_config import PULSE_APPLIANCE, PULSE_USERNAME, PULSE_PASSWORD, \
    CHECK_SSL, RSA_FILE, RSA_PUB_FILE

urllib3.disable_warnings()


class HTTPException(Exception):
    pass


class PulseNACClient(ThirdPartyInterface):
    @staticmethod
    def get_api_token(nac, username, password, rsa_file, rsa_pub_file) -> str:
        """
        Obtains an API Key from the Pulse NAC appliance if a valid token has not been previously saved using the saved
        credentials.  Token returned is a bytes array which needs to be .decoded()
        :param nac: IP or hostname of Pulse NAC appliance
        :param username:
        :param password:
        :return: bytes encoded api key with ':' appended
        """

        logger = logging.getLogger()
        jwt_file = 'third_party_clients/pulse_nac/.jwt'

        def nac_auth(pulse, uname, psswd):
            r = requests.get('https://{}/api/v1/auth'.format(pulse), auth=(uname, psswd), headers=headers,
                             verify=False)
            r.close()
            if r.ok:
                try:
                    private_key = open(rsa_file, 'r').read()
                    key = serialization.load_ssh_private_key(private_key.encode(), password=b'')
                    token = jwt.encode(payload=r.json(), key=key, algorithm='RS256')
                    with open(jwt_file, 'w') as jwt_out:
                        logger.debug('Saving new token to .jwt')
                        jwt_out.write(token)
                except FileNotFoundError as e:
                    logger.warning('SSH RSA private key file not found: {}, '
                                   '### Pulse NAC enforcement will not operate. ###'.format(e))
                    return b'abc123'
                logger.debug('Username/password authentication successful, returning token')
                return base64.b64encode(r.json()['api_key'].encode() + ':'.encode())
            else:
                logger.warning('Invalid credentials, unable to retrieve API key, '
                               '### Pulse NAC enforcement will not operate. ###')
                logger.warning('Pulse NAC authentication error: {}'.format(r.reason))
                return b'abc123'

        headers = {'Content-Type': 'application/json'}
        token_error = False
        # Check to see if valid token exists
        if os.path.isfile(jwt_file):
            with open(jwt_file, 'r') as jwt_in:
                logger.debug('.jwt exists reading.')
                token = jwt_in.read()
            try:
                public_key = open(rsa_pub_file, 'r').read()
            except FileNotFoundError as e:
                logger.warning('ssh RSA pub key not found: {}'.format(e))
                exit()
            # Keyfile exists
            key = serialization.load_ssh_public_key(public_key.encode(), backend=default_backend())
            try:
                jwt_token = jwt.decode(jwt=token, key=key, algorithms=['RS256'])
            except jwt.exceptions.DecodeError:
                logger.warning('Token loaded from file not able to be decoded')
                token_error = True
            if not token_error:
                logger.debug('Do auth check to ensure token works')
                # Format token for header
                ht = base64.b64encode(jwt_token.get('api_key').encode() + ':'.encode())
                headers['Authorization'] = 'Basic {}'.format(ht.decode())
                logger.debug('Debug headers:{}'.format(headers))
                ac = requests.get('https://{}/api/v1/system/system-information'.format(nac), headers=headers,
                                  verify=False)
                ac.close()
                if ac.ok:
                    logger.debug('Token from file valid, returning')
                    return base64.b64encode(jwt_token.get('api_key').encode() + ':'.encode())
                else:
                    logger.info('Token from file not valid for authentication, initializing auth to obtain new token')
                    return nac_auth(nac, username, password)
            else:
                logger.info('Token not decoded from file, initializing auth to obtain new token')
                return nac_auth(nac, username, password)
        else:
            logger.debug('.jwt file does not exist, initializing auth to obtain new token')
            return nac_auth(nac, username, password)

    def __init__(self):
        self.urlbase = 'https://{}'.format(PULSE_APPLIANCE)
        self.token = self.get_api_token(PULSE_APPLIANCE, PULSE_USERNAME, PULSE_PASSWORD, RSA_FILE, RSA_PUB_FILE)
        self.headers = {'Content-Type': 'application/json'}
        self.verify = CHECK_SSL
        self.logger = logging.getLogger()
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def block_host(self, host):
        self.logger.debug('Pulse NAC host quarantine request:{}:{}'.format(host.ip, host.mac_addresses))
        try:
            res = self._quarantine_endpoint(host.ip)
            if res.status_code == 204:
                self.logger.info('Pulse NAC Initiated quarantine for host: {}, {}'.format(host.ip, host.mac_addresses))
                mac_address = self._retrieve_endpoint(host.ip)
                self.logger.debug('Block mac_address return: {}'.format(mac_address))
                return mac_address
            else:
                self.logger.info('Pulse NAC unable to quarantine host: {} because: {}'.format(host.ip, res.reason))
                return []
        except HTTPException:
            pass
        return []

    def unblock_host(self, host):
        # mac_addresses = host.mac_addresses
        mac_addresses = host.blocked_elements.get(self.__class__.__name__, [])
        if len(mac_addresses) < 1:
            mac_addresses = self._retrieve_endpoint(host.ip)
            self.logger.debug('Unblock, no supplied MAC, return from get session {}'.format(mac_addresses))

        if len(mac_addresses) < 1:
            self.logger.warning('Unable to obtain MAC address and unquarantine host with IP {}'.format(host.ip))
            return [host.ip]
        else:
            for mac_address in mac_addresses:
                self.logger.debug('Pulse NAC unblocking request host:{}, {}'.format(host.ip, host.mac_addresses))
                try:
                    res = self._unquarantine_endpoint(mac_address)

                    if res.status_code == 204:
                        self.logger.info('Pulse NAC Initiated unquarantine for host: {}, {}'.format(
                            host.ip, mac_address))
                    elif res.status_code == 400:
                        self.logger.info(
                            'Pulse NAC Initiated unquarantine for a host that can\'t be found: {}, {}'.format(
                                host.ip, mac_address))
                    else:
                        self.logger.info('Pulse NAC unable to unquarantine host: {}, {} because: {}, '
                                         'status_code:{}'.format(host.ip, mac_address, res.reason, res.status_code))
                except HTTPException:
                    print('http exception')
                    pass
        return mac_addresses

    def groom_host(self, host) -> dict:
        self.logger.warning('Pulse NAC client does not implement host grooming')
        return []

    def block_detection(self, detection):
        self.logger.warning('Pulse NAC client does not implement detection-based blocking')
        return []

    def unblock_detection(self, detection):
        self.logger.warning('Pulse NAC client does not implement detection-based blocking')
        return []

    def _quarantine_endpoint(self, ip):
        """
        Block endpoint (IP) via Admission Control

        :param ip: IP to block
        :return:  reqeust's response object
        """
        body = json.dumps({
            'event-name': 'quarantine-endpoint',
            'srcip': '{}'.format(ip)
        })
        headers = {**self.headers, **{'Authorization': 'Basic ' + self.token.decode('utf-8')}}
        self.logger.debug('headers: {}'.format(headers))
        self.logger.debug('body: {}'.format(body))
        response = requests.put(self.urlbase + '/api/v1/integration/sessions',
                                headers=headers, data=body, verify=self.verify)
        return response

    def _retrieve_endpoint(self, ip):
        """
        Obtain an endpoint's (IP) MAC address that is registered with Admission Control

        :param ip: IP of host session
        :return:  reqeusts' response object
        """
        headers = {**self.headers, **{'Authorization': 'Basic ' + self.token.decode('utf-8')}}
        response = requests.get(self.urlbase + '/api/v1/integration/sessions/{}'.format(ip), headers=headers,
                                verify=self.verify)
        data = response.json()['data']
        return [i['macaddr'] for i in data]

    def _unquarantine_endpoint(self, mac):
        """
        Unblock endpoint (MAC) via Admission Control

        :param mac: MAC to unblock
        :return:  reqeusts' response object
        """
        headers = {**self.headers, **{'Authorization': 'Basic ' + self.token.decode('utf-8')}}
        body = json.dumps({
            'event-name': 'clear-quarantined-endpoint',
            'macaddr': '{}'.format(mac)
        })
        response = requests.put(self.urlbase + '/api/v1/integration/sessions', headers=headers, data=body,
                                verify=self.verify)
        return response
