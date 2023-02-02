import logging
import requests
from urllib3.exceptions import InsecureRequestWarning
from third_party_clients.cisco_amp.amp_config import URL, CLIENT_ID, API_KEY
from third_party_clients.third_party_interface import ThirdPartyInterface

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class AMPClient(ThirdPartyInterface):
    def __init__(self):
        self.logger = logging.getLogger()
        self._check_connection()
        # Instantiate parent class
        ThirdPartyInterface.__init__ (self)

    def block_host(self, host) -> list[str]:
        self.logger.info(f"Processing block request for host with IP: {host.ip}")
        cguid = self._get_connector_guid(host.ip)
        isolation_state = self._get_block_state(cguid)
        if isolation_state == 'not_isolated' or isolation_state == 'pending_stop':
            self._block_host_by_connector_guid(cguid)
            isolation_state = self._get_block_state(cguid)
            if not isolation_state == 'pending_start' or isolation_state == 'isolated':
                self.logger.error("Expected isolation status to be 'pending_start' or 'isolated'.")
                exit()
        else:
            self.logger.info("Host already blocked. Skipping host.")
        self.logger.info("Host successfully blocked.")
        return [host.ip]

    def unblock_host(self, host) -> list[str]:
        self.logger.info(f"Processing unblock request for host with IP: {host.ip}")
        cguid = self._get_connector_guid(host.ip)
        isolation_state = self._get_block_state(cguid)
        if isolation_state == 'isolated' or isolation_state == 'pending_start':
            self._unblock_host_by_connector_guid(cguid)
            isolation_state = self._get_block_state(cguid)
            if not isolation_state == 'pending_stop' or isolation_state == 'not_isolated':
                self.logger.error("Expected isolation status to be 'pending_stop' or 'not_isolated'.")
                exit()
        else:
            self.logger.info("Host already unblocked. Skipping host.")
        self.logger.info("Host successfully unblocked.")
        return [host.ip]
    
    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("Cisco AMP client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("Cisco AMP client does not implement detection-based blocking")
        return []

    def _check_connection(self):
        try:
            self.logger.info("Performing Cisco AMP connection check.")
            api_endpoint = 'version'
            response = requests.get(
                url=f'{URL}/v1/{api_endpoint}',
                verify=False,
                auth=(CLIENT_ID, API_KEY)
                )
            response.raise_for_status()
            self.logger.info("Connection check successful.")
        except:
            self.logger.info("Cisco AMP connection check failed.")

    def _get_connector_guid(self, ip):
        self.logger.info(f"Querying unique connector guid for host with IP: {ip}")
        api_endpoint = f'computers?internal_ip={ip}'
        response = requests.get(
            url=f'{URL}/v1/{api_endpoint}',
            verify=False,
            auth=(CLIENT_ID, API_KEY)
            )
        response.raise_for_status()
        data = response.json()
        
        if data['metadata']['results']['total'] > 1:
            self.logger.error(f'Found more than 1 host with IP {ip}')
            exit()
        elif data['metadata']['results']['total'] == 0:
            self.logger.error(f'Found no host with IP {ip}')
            exit()
        else:
            cguid = data['data'][0]['connector_guid']
            self.logger.info(f"Connector guid received: {cguid}")
            return cguid

    def _get_block_state(self, connector_guid):
        self.logger.info(f"Querying isolation state for host identified by connector guid {connector_guid}.")
        api_endpoint = f'computers/{connector_guid}/isolation'
        response = requests.get(
            url=f'{URL}/v1/{api_endpoint}',
            verify=False,
            auth=(CLIENT_ID, API_KEY)
            )
        response.raise_for_status()
        data = response.json()
        
        if not data['data']['available']:
            self.logger.error(f"Isolation unavailable for host identified by connector guid {connector_guid}.")
            exit()
        else:
            isolation_state = data['data']['status']
            self.logger.info(f"Isolation available. Isolation state received: {isolation_state}")
            return isolation_state

    def _block_host_by_connector_guid(self, connector_guid):
        self.logger.info(f"Requesting isolation of host identified by connector guid {connector_guid}.")
        api_endpoint = f'computers/{connector_guid}/isolation'
        response = requests.put(
            url=f'{URL}/v1/{api_endpoint}',
            verify=False,
            auth=(CLIENT_ID, API_KEY)
            )
        response.raise_for_status()

    def _unblock_host_by_connector_guid(self, connector_guid):
        self.logger.info(f"Requesting to stop isolation of host identified by connector guid {connector_guid}.")
        api_endpoint = f'computers/{connector_guid}/isolation'
        response = requests.delete(
            url=f'{URL}/v1/{api_endpoint}',
            verify=False,
            auth=(CLIENT_ID, API_KEY)
            )
        response.raise_for_status()