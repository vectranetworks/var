import logging
import requests
import urllib3
import json
import keyring
from third_party_clients.third_party_interface import ThirdPartyInterface
from third_party_clients.meraki.meraki_config import MERAKI_URL, VERIFY

urllib3.disable_warnings()


class HTTPException(Exception):
    pass


class MerakiClient(ThirdPartyInterface):
    @staticmethod
    def get_orgs(urlbase, headers, verify, logger) -> list:
        """
        Obtains list of organization IDs from Meraki API
        :return: list of organization IDs
        """
        results = requests.get(urlbase + '/organizations', headers=headers, verify=verify)
        if results.ok:
            return [org.get('id') for org in results.json()]
        else:
            logger.error('Unable to retrieve organizations for Meraki API.  Error message:{}'.format(results.reason))
            return []

    def __init__(self):
        self.urlbase = MERAKI_URL.strip('/')
        self.token = keyring.get_password('VAE', 'Meraki')
        self.headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self.token}
        self.logger = logging.getLogger()
        self.verify = VERIFY
        self.orgs = self.get_orgs(self.urlbase, self.headers, self.verify, self.logger)
        # Instantiate parent class
        ThirdPartyInterface.__init__(self)

    def block_host(self, host):
        self.logger.info('Meraki host block request for:{}:{}'.format(host.ip, host.mac_addresses))
        # Retrieve client_id
        # [{'id': 'kcd012f', 'net_id': 'N_644014746713985158', 'mac': '30:24:a9:96:b9:b4', 'description': 'BEDENNB131'}]
        client_list = self._get_client_id(host.ip, host.mac_addresses)
        if len(client_list) < 1:
            self.logger.info('Unable to find client ID for:{}:{}, not blocking.'.format(host.ip, host.mac_addresses))
        if len(client_list) > 1:
            self.logger.info('More than 1 client found for:{}:{}, not blocking.'.format(host.ip, host.mac_addresses))
        if len(client_list) == 1:
            self.logger.info('1 client found for:{}:{}, blocking.'.format(host.ip, client_list[0]['id']))
            res = self._block_client(client_list[0])
            if res.ok:
                self.logger.info('Client {} with ID {} successfully blocked.'.format(client_list[0]['description'],
                                                                                     client_list[0]['id']))
                return ['{}:{}'.format(client_list[0]['id'], client_list[0]['net_id'])]
            else:
                self.logger.info('Error blocking client.  Error message: {}.'.format(res.reason))
                return []

    def unblock_host(self, host):
        client_network = host.blocked_elements.get(self.__class__.__name__, [])
        self.logger.debug('client_network:{}'.format(client_network))
        client_id = client_network[0].split(':')[0]
        network_id = client_network[0].split(':')[1]
        self.logger.debug('Meraki host unblock request for host:{} client:{}, network:{}'.format(
            host.name, client_id, network_id))
        res = self._unblock_client(client_id, network_id)
        if res.ok:
            self.logger.debug('Meraki host unblock request successful for host:{} client:{}, network:{}'.format(
                host.name, client_id, network_id))
            return [client_network]
        else:
            self.logger.debug('Meraki host unblock request unsuccessful for host:{} client:{}, network:{}'.format(
                host.name, client_id, network_id))
            return [client_network]

    def block_detection(self, detection):
        self.logger.warning('Meraki client does not implement detection-based blocking')
        return []

    def unblock_detection(self, detection):
        self.logger.warning('Meraki client does not implement detection-based blocking')
        return []

    def _get_networks(self):
        """
        Obtains and returns a list of network IDs based on the list of organizations.
        :return: list of networks
        """
        networks = []
        for org in self.orgs:
            result = None
            result = requests.get(url=self.urlbase + '/organizations/{}/networks/'.format(org), headers=self.headers,
                                  verify=self.verify)
            for item in result.json():
                networks.append(item.get('id'))
        return networks

    def _get_client_id(self, ip, macs):
        """
        Searches for the IP of the client over the list of retrieved network IDs, falls back to searching by MAC when
        no result based on IP only if a single MAC is provided.
        :param ip: IP of host to search for
        :param macs: MAC list of host to search for
        :last_seen: last seen timestamp
        :return: A list of dictionary items containing the network ID and client ID, mac, and hostname
         of the host with the provided IP
        """
        networks = self._get_networks()
        ret_list = []
        for net_id in networks:
            params = {'ip': ip}
            result = requests.get(url=self.urlbase + '/networks/{}/clients'.format(net_id), headers=self.headers,
                                  params=params, verify=self.verify)
            if len(result.json()) > 0:
                ret_list += [{'id': i['id'], 'net_id': net_id, 'mac': i['mac'], 'description': i['description']}
                             for i in result.json()]
        if len(ret_list) < 1 and len(macs) == 1:
            for net_id in networks:
                params = {'mac': macs[0]}
                result = requests.get(url=self.urlbase + '/networks/{}/clients'.format(net_id), headers=self.headers,
                                      params=params, verify=self.verify)
                if len(result.json()) > 0:
                    ret_list += [{'id': i['id'], 'net_id': net_id, 'mac': i['mac'], 'description': i['description']}
                                 for i in result.json()]
        return ret_list

    def _block_client(self, client):
        """
        Block client by updating client's policy to 'Block'.

        :param client: Client object
        # {'id': 'kcd012f', 'net_id': 'N_644014746713985158', 'mac': '30:24:a9:96:b9:b4', 'description': 'BEDENNB131'}
        :return:  reqeust's response object
        """
        # https://developer.cisco.com/meraki/api-latest/#!update-network-client-policy
        body = {"devicePolicy": "Blocked"}
        response = requests.put(self.urlbase + '/networks/{}/clients/{}/policy'.format(client.get('net_id'),
                                                                                       client.get('id')),
                                headers=self.headers, data=json.dumps(body), verify=self.verify)
        return response

    def _unblock_client(self, client_id, net_id):
        """
        Unblock client by updating client's policy to 'Normal'
        :param client_id: client id
        :param net_id: network id
        :return:  reqeust's response object
        """
        body = {"devicePolicy": "Normal"}
        response = requests.put(self.urlbase + '/networks/{}/clients/{}/policy'.format(net_id, client_id),
                                headers=self.headers, data=json.dumps(body), verify=self.verify)
        return response
