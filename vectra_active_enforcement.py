import logging
import time
import keyring
import requests
import logging
import ipaddress
import argparse
import vat.vectra as vectra
from datetime import datetime
from requests import HTTPError
from typing import Union, Optional, Dict
from vectra_active_enforcement_consts import VectraHost, VectraDetection
from third_party_clients.fortinet import fortinet
from third_party_clients.vmware import vmware
from third_party_clients.pan import pan
from third_party_clients.cisco_ise import ise
from third_party_clients.cisco_amp import amp
from third_party_clients.trendmicro_apexone import apex_one
from third_party_clients.test_client import test_client
from third_party_clients.pulse_nac import pulse_nac
from third_party_clients.bitdefender import bitdefender
from third_party_clients.meraki import meraki
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from config import (COGNITO_URL, COGNITO_TOKEN, BLOCK_HOST_TAG, LOG_TO_FILE, LOG_FILE, SLEEP_MINUTES,
                    NO_BLOCK_HOST_GROUP_NAME, BLOCK_HOST_THREAT_CERTAINTY, BLOCK_HOST_DETECTION_TYPES_MIN_TC_SCORE,
                    BLOCK_HOST_DETECTION_TYPES, EXTERNAL_BLOCK_HOST_TC, EXTERNAL_BLOCK_DETECTION_TAG,
                    BLOCK_HOST_GROUP_NAME, EXTERNAL_BLOCK_DETECTION_TYPES)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


HostDict = Dict[str, VectraHost]
DetectionDict = Dict[str, VectraDetection]


if LOG_TO_FILE:
    logging.basicConfig(filename=LOG_FILE, format='%(asctime)s %(message)s',
                        encoding='utf-8', level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.DEBUG)


class HTTPException(Exception):
    def __init__(self, response):
        """ 
        Custom exception class to report possible API errors
        The body is contructed by extracting the API error code from the requests.Response object
        """
        try:
            r = response.json()
            if 'detail' in r:
                detail = r['detail']
            elif 'errors' in r:
                detail = r['errors'][0]['title']
            elif '_meta' in r:
                detail = r['_meta']['message']
            else:
                detail = response.content
        except Exception:
            detail = response.content
        body = 'Status code: {code} - {detail}'.format(
            code=str(response.status_code), detail=detail)
        super().__init__(body)


class VectraClient(vectra.VectraClientV2_2):

    def __init__(self, url=None, token=None, verify=False):
        """
        Initialize Vectra client
        :param url: IP or hostname of Vectra brain - required
        :param token: API token for authentication - required
        :param verify: verify SSL - optional
        """
        vectra.VectraClientV2_2.__init__(
            self, url=url, token=token, verify=verify)
        self.logger = logging.getLogger('VectraClient')

    def get_hosts_in_group(self, group_name: str) -> HostDict:
        """
        Get a dictionnary of all hosts present in a group. 
        :param group_name: name of the group for which to return the hosts
        :rtype: HostDict
        """
        hosts = {}
        r = self.get_all_groups(name=group_name)
        try:
            for page in r:
                for group in page.json()['results']:
                    for member in group['members']:
                        host = self.get_host_by_id(host_id=member['id']).json()
                        if host['id'] not in hosts:
                            hosts[host['id']] = VectraHost(host)
            return hosts
        except KeyError:
            raise HTTPError(page.text)

    def get_scored_hosts(self, tc_tuple) -> HostDict:
        """
        Get a dictionnary of all hosts above given threat/certainty threshold
        :param threat_gte: threat score threshold
         :param certainty_gte: certainty score threshold
        :rtype: HostDict
        """
        hosts = {}
        try:
            threat_gte, condition, certainty_gte = tc_tuple
            if not isinstance(threat_gte, int) and isinstance(certainty_gte, int):
                raise ValueError
            if not condition in ['and', 'or']:
                raise ValueError
        except ValueError:
            self.logger.error(
                'Invalid Threat/Certainty tuple provided in the BLOCK_HOST_THREAT_CERTAINTY parameter')
            exit(99)

        if condition == 'and':
            r = self.get_all_hosts(threat_gte=threat_gte,
                                   certainty_gte=certainty_gte, all=True)
            for page in r:
                if page.status_code not in [200, 201, 204]:
                    raise HTTPException(page)
                for host in page.json().get('results', []):
                    hosts[host['id']] = VectraHost(host)
        else:
            r = self.get_all_hosts(threat_gte=threat_gte, all=True)
            for page in r:
                if page.status_code not in [200, 201, 204]:
                    raise HTTPException(page)
                for host in page.json().get('results', []):
                    hosts[host['id']] = VectraHost(host)
            r = self.get_all_hosts(certainty_gte=certainty_gte, all=True)
            for page in r:
                if page.status_code not in [200, 201, 204]:
                    raise HTTPException(page)
                for host in page.json().get('results', []):
                    hosts[host['id']] = VectraHost(host)

        return hosts

    def get_tagged_hosts(self, tag: str) -> HostDict:
        """
        Get a dictionnary of all hosts that contain given tag
        :param tag: tag to search
        :rtype: HostDict
        """
        hosts = {}
        r = self.get_all_hosts(tags=tag, all=True)
        for page in r:
            if page.status_code not in [200, 201, 204]:
                raise HTTPException(page)
            for host in page.json().get('results', []):
                hosts[host['id']] = VectraHost(host)
        return hosts

    def get_hosts_with_detection_types(self, detection_types: list, block_host_detections_types_min_host_tc: tuple) -> HostDict:
        """
        Get a dictionnary of all hosts containing detections of given type
        :param detection_types: list of all detections types
        :rtype: HostDict
        """
        hosts = {}
        try:
            threat_gte, condition, certainty_gte = block_host_detections_types_min_host_tc
            if not isinstance(threat_gte, int) and isinstance(certainty_gte, int):
                raise ValueError
            if not condition in ['and', 'or']:
                raise ValueError
        except ValueError:
            self.logger.error(
                'Invalid Threat/Certainty tuple provided in the BLOCK_HOST_THREAT_CERTAINTY parameter')
            exit(99)

        detections = self.get_detections_by_type(
            detection_types=detection_types)
        for detection in detections.values():
            host_id = detection['src_host']['id']
            host = self.get_host_by_id(host_id=host_id).json()
            if condition == 'and':
                if host['threat'] > threat_gte and host['certainty'] > certainty_gte:
                    hosts[host['id']] = VectraHost(host)
            elif condition == 'or':
                if host['threat'] > threat_gte or host['certainty'] > certainty_gte:
                    hosts[host['id']] = VectraHost(host)
            else:
                continue
        return hosts

    def get_noblock_hosts(self, no_block_group: Optional[str] = None) -> HostDict:
        """
        Get all host IDs which should not be blocked
        :param no_block_group: group name containing hosts which should never be blocked - optional
        :rtype: HostDict
        """
        return self.get_hosts_in_group(group_name=no_block_group) if no_block_group else {}

    def get_hosts_to_block(self,
                           block_tag: Optional[str] = None,
                           min_tc_score: Optional[tuple] = None,
                           block_host_group_name: Optional[str] = None,
                           block_host_detection_types: list = [],
                           block_host_detections_types_min_host_tc: tuple = (
                               0, 'and', 0)
                           ) -> HostDict:
        """
        Get all host IDs which should be blocked given the parameters. 
        :param block_tag: tag defining hosts that need to be blocked - optional
        :param min_tc_score: tuple of (threat, certainty) to query hosts exceeding this threshold - optional
        :param block_host_detection_types: list of detections types which if present on a host will cause the host to be blocked - optional
        :rtype: HostDict
        """
        tagged_hosts = self.get_tagged_hosts(
            tag=block_tag) if block_tag else {}
        scored_hosts = self.get_scored_hosts(
            tc_tuple=min_tc_score) if isinstance(min_tc_score, tuple) else {}
        group_members = self.get_hosts_in_group(
            group_name=block_host_group_name)
        hosts_with_detection_types = self.get_hosts_with_detection_types(
            block_host_detection_types, block_host_detections_types_min_host_tc) if block_host_detection_types else {}
        return {**tagged_hosts, **scored_hosts, **group_members, **hosts_with_detection_types}

    def get_tagged_detections(self, tag: str) -> DetectionDict:
        """
        Get a dictionnary of all detections that contain given tag
        :param tag: tag to search
        :rtype: DetectionDict
        """
        detections = {}
        r = self.get_all_detections(tags=tag)
        for page in r:
            if page.status_code not in [200, 201, 204]:
                raise HTTPException(page)
            for detection in page.json().get('results', []):
                # for some reason the API does substring matching, so we check
                if tag in detection['tags']:
                    detections[detection['id']] = VectraDetection(detection)
        return detections

    def get_detections_by_type(self, detection_types: list = []) -> DetectionDict:
        """
        Get a dictionnary of all detections mathing the given types. 
        :param detection_types: list of all detection types to match. 
        :rtype: DetectionDict
        """
        detections = {}
        if len(detection_types) < 1:
            return detections
        else:
            r = self.get_all_detections(
                detection_type=detection_types, state='active')
            for page in r:
                if page.status_code not in [200, 201, 204]:
                    raise HTTPException(page)
                for detection in page.json().get('results', []):
                    detections[detection['id']] = VectraDetection(detection)
        return detections

    def get_detections_on_host(self, host_id: int) -> DetectionDict:
        """
        Get a dictionnary of all detections on a given host, matching by id.  
        :param host_id: ID of the host for which to return all detections. 
        :rtype: DetectionDict
        """
        # Get all detection IDs on hosts
        detection_ids = set()
        host = self.get_host_by_id(
            host_id=host_id, fields='detection_set').json()
        for detection in host.get('detection_set', []):
            detection_ids.add(detection.rsplit('/', 1)[1])
        # Get individual detections
        detections = {}
        for detection_id in detection_ids:
            r = self.get_detection_by_id(detection_id=detection_id)
            detection = r.json()
            # Ignore info detections, custom and inactive ones
            if detection.get('category') != 'INFO' and detection.get('state') == 'active' and detection.get('is_triaged') == False:
                detections[detection['id']] = VectraDetection(detection)
        return detections

    def get_detections_on_hosts_in_group(self, group_name: str) -> DetectionDict:
        """
        Get a dictionnary of all detections present on members of the host group given in parameter. 
        :param group_name: name of the host group to query 
        :rtype: DetectionDict
        """
        detections = {}
        r = self.get_all_groups(name=group_name)
        for page in r:
            for group in page.json()['results']:
                for member in group['members']:
                    detections.update(
                        self.get_detections_on_host(host_id=member['id']))
        return detections

    def get_detections_on_scored_host(self, min_host_tc_score: tuple) -> DetectionDict:
        """
        Get a dictionnary of all detections present on hosts exceeding the threat/certainty threshold.. 
        :param host_threat_gte: min threat score of hosts to match
        :param host_certainty_gte: min certainty score of hosts to match 
        :rtype: DetectionDict
        """
        detections = {}
        hosts = self.get_scored_hosts(tc_tuple=min_host_tc_score)
        # iterate through the matching host IDs
        for host_id in hosts.keys():
            detections.update(self.get_detections_on_host(host_id=host_id))
        return detections

    def get_noblock_detections(self, no_block_group: Optional[str] = None) -> DetectionDict:
        """
        Get a dict of all detection IDs which should not be blocked given the parameters. 
        :param no_block_group: name of the host group whose member detections should never be blocked - optional
        :rtype: DetectionDict
        """
        return self.get_detections_on_hosts_in_group(group_name=no_block_group) if no_block_group else {}

    def get_detections_to_block(self, block_tag: Optional[str] = None, detection_types_to_block: Optional[list] = None, min_host_tc_score: Optional[tuple] = None) -> DetectionDict:
        """
        Get a dict of all detection IDs which should be blocked given the parameters. 
        :param block_tag: tag defning detections which should be blocked or unblocked - optional
        :param detection_types_to_block: list of detection types to block, regardless of score
        :param min_host_tc_score: tuple (int, int) of min host threat/certainty score for which,\
            if exceeded to block all detections on host. 
        :rtype: DetectionDict
        """
        tagged_detections = self.get_tagged_detections(
            tag=block_tag) if block_tag else {}
        typed_detections = self.get_detections_by_type(
            detection_types=detection_types_to_block) if detection_types_to_block else {}
        detections_of_scored_hosts = self.get_detections_on_scored_host(
            min_host_tc_score=min_host_tc_score) if min_host_tc_score else {}
        return {**tagged_detections, **typed_detections, **detections_of_scored_hosts}


class VectraActiveEnforcement(object):

    def __init__(self,
                 third_party_clients: list,
                 vectra_api_client: VectraClient,
                 block_host_tag: Optional[str],
                 block_host_tc_score: tuple,
                 block_host_group_name: Optional[str],
                 block_host_detection_types: list,
                 block_host_detections_types_min_host_tc: tuple,
                 no_block_host_group_name: Optional[str],
                 external_block_host_tc: tuple,
                 external_block_detection_types: list,
                 external_block_detection_tag: Optional[str],
                 ):
        # Generic setup
        self.logger = logging.getLogger()
        self.third_party_clients = third_party_clients
        self.vectra_api_client = vectra_api_client
        # Internal (un)blocking variables
        self.block_host_tag = block_host_tag
        self.block_host_tc_score = block_host_tc_score
        self.block_host_group_name = block_host_group_name
        self.block_host_detection_types = block_host_detection_types
        self.block_host_detections_types_min_host_tc = block_host_detections_types_min_host_tc
        self.no_block_host_group_name = no_block_host_group_name
        # External (un)blocking variables
        self.external_block_host_tc = external_block_host_tc
        self.external_block_detection_types = external_block_detection_types
        self.external_block_detection_tag = external_block_detection_tag

    @staticmethod
    def _get_dict_keys_intersect(dict1, dict2):
        """
        Function that return dict of all keys present in both dict1 and dict2
        """
        result_dict = {}
        for key, value in dict1.items():
            if key in dict2.keys():
                result_dict[key] = value
        return result_dict

    @staticmethod
    def _get_dict_keys_relative_complement(dict1, dict2):
        """
        Function that returns dict of all keys present in dict1 and NOT in dict 2
        """
        result_dict = {}
        for key, value in dict1.items():
            if key not in dict2.keys():
                result_dict[key] = value
        return result_dict

    def get_hosts_to_block_unblock(self):
        """
        Get all host IDs matching the criteria to be blocked or unblocked
        :rtype: list
        """
        # Set of all host IDs that should never be blocked
        no_block_hosts = self.vectra_api_client.get_noblock_hosts(
            no_block_group=self.no_block_host_group_name)
        # Get a dict of hosts to block
        matching_hosts = self.vectra_api_client.get_hosts_to_block(
            block_tag=self.block_host_tag,
            min_tc_score=self.block_host_tc_score,
            block_host_group_name=self.block_host_group_name,
            block_host_detection_types=self.block_host_detection_types,
            block_host_detections_types_min_host_tc=self.block_host_detections_types_min_host_tc
        )
        # Get a dict of hosts already blocked
        blocked_hosts = self.vectra_api_client.get_tagged_hosts(
            tag='VAE Blocked')
        self.logger.info('Found {} already blocked hosts on Vectra'.format(
            str(len(blocked_hosts.keys()))))
        # Find blocked hosts that should be unblocked
        hosts_wrongly_blocked = self._get_dict_keys_intersect(
            blocked_hosts, no_block_hosts)
        self.logger.info('Found {} blocked hosts that are now part of the no-block lists'.format(
            str(len(hosts_wrongly_blocked.keys()))))
        # Compute hosts that should be blocked
        hosts_to_block = self._get_dict_keys_relative_complement(
            matching_hosts, blocked_hosts)
        # Take into account exclusions
        hosts_to_block = self._get_dict_keys_relative_complement(
            hosts_to_block, no_block_hosts)
        self.logger.info('Found {} hosts that need to be blocked'.format(
            str(len(hosts_to_block.keys()))))
        # Compute hosts that should be unblocked
        hosts_to_unblock = self._get_dict_keys_relative_complement(
            blocked_hosts, matching_hosts)
        # Add wrongly blocked hosts
        hosts_to_unblock = {**hosts_to_unblock, **hosts_wrongly_blocked}
        self.logger.info('Found {} hosts that need to be unblocked'.format(
            str(len(hosts_to_unblock.keys()))))
        return hosts_to_block, hosts_to_unblock

    def get_detections_to_block_unblock(self):
        # Get a list of all detections that should be unblocked or never blocked
        no_block_detections = self.vectra_api_client.get_noblock_detections(
            no_block_group=self.no_block_host_group_name)
        # Get a dict of detections to block
        matching_detections = self.vectra_api_client.get_detections_to_block(
            block_tag=self.external_block_detection_tag,
            detection_types_to_block=self.external_block_detection_types,
            min_host_tc_score=self.external_block_host_tc
        )
        # Get a dict of detections already blocked
        blocked_detections = self.vectra_api_client.get_tagged_detections(
            tag='VAE Blocked')
        self.logger.info('Found {} already blocked detections on Vectra'.format(
            str(len(blocked_detections.keys()))))
        # Find blocked detections that should be unblocked
        detections_wrongly_blocked = self._get_dict_keys_intersect(
            blocked_detections, no_block_detections)
        self.logger.info('Found {} blocked detections that are now part of the no-block lists'.format(
            str(len(detections_wrongly_blocked.keys()))))
        # Compute detections that should be blocked
        detections_to_block = self._get_dict_keys_relative_complement(
            matching_detections, blocked_detections)
        # Take into account exclusions
        detections_to_block = self._get_dict_keys_relative_complement(
            detections_to_block, no_block_detections)
        self.logger.info('Found {} detections that need to be blocked'.format(
            str(len(detections_to_block.keys()))))
        # Compute detections that should be unblocked
        detections_to_unblock = self._get_dict_keys_relative_complement(
            blocked_detections, matching_detections)
        # Add wrongly blocked detections
        detections_to_unblock = {
            **detections_to_unblock, **detections_wrongly_blocked}
        self.logger.info('Found {} detections that need to be unblocked'.format(
            str(len(detections_to_unblock.keys()))))
        return detections_to_block, detections_to_unblock

    def block_hosts(self, hosts_to_block):
        for host_id, host in hosts_to_block.items():
            for third_party_client in self.third_party_clients:
                try:
                    # Quarantaine endpoint
                    blocked_elements = third_party_client.block_host(host=host)
                    self.logger.info('Blocked host {id} on client {client}'.format(
                        id=host_id, client=third_party_client.__class__.__name__))
                    # Set a "VAE Blocked" to set the host as being blocked and registed what elements were blocked in separate tags
                    tag_to_set = ['VAE Blocked']
                    if len(blocked_elements) < 1:
                        self.logger.warning(
                            'Did not find any elements to block on host ID {}'.format(host_id))
                    for element in blocked_elements:
                        tag_to_set.append('VAE ID:{client_class}:{id}'.format(
                            client_class=third_party_client.__class__.__name__, id=element))
                    self.vectra_api_client.set_host_tags(
                        host_id=host_id, tags=tag_to_set, append=True)
                    self.vectra_api_client.set_host_note(host_id=host_id, note='Automatically blocked on {}'.format(
                        datetime.now().strftime('%d %b %Y at %H:%M:%S')))
                    self.logger.debug('Added Tags to host')
                except HTTPException as e:
                    self.logger.error(
                        'Error encountered trying to block Host ID {}: {}'.format(host.id, str(e)))

    def unblock_hosts(self, hosts_to_unblock):
        for host_id, host in hosts_to_unblock.items():
            if len(host.blocked_elements) < 1:
                self.logger.error(
                    'Could not find what was blocked on host {}'.format(host.name))
                continue
            for third_party_client in self.third_party_clients:
                try:
                    unblocked_elements = third_party_client.unblock_host(host)
                    for element in unblocked_elements:
                        self.logger.debug(
                            'Unblocked element {}'.format(element))
                    self.logger.info('Unquaratained host {id} on client {client}'.format(
                        id=host_id, client=third_party_client.__class__.__name__))
                    # Remove all tags set by this script from the host.
                    # Sometimes a host can have both a block and unblock tag, we need to correct this.
                    if 'block' in host.tags:
                        self.logger.warning(
                            'Host {} is in no-block list but has a "block" tag. Removing tag..'.format(host['name']))
                        host.tags.remove('block')
                    self.vectra_api_client.set_host_tags(
                        host_id=host_id, tags=host.tags, append=False)
                    self.vectra_api_client.set_host_note(host_id=host_id, note='Automatically unblocked on {}'.format(
                        datetime.now().strftime('%d %b %Y at %H:%M:%S')))
                    self.logger.debug('Removed tags')
                except HTTPException as e:
                    self.logger.error(
                        'Error encountered trying to unblock Host ID{}: {}'.format(host.id, str(e)))

    def block_detections(self, detections_to_block):
        for detection_id, detection in detections_to_block.items():
            for third_party_client in self.third_party_clients:
                try:
                    # Quarantaine endpoint
                    blocked_elements = third_party_client.block_detection(
                        detection=detection)
                    # Set a "VAE Blocked" to set the detection as being blocked and registed what elements were blocked in separate tags
                    tag_to_set = ['VAE Blocked']
                    if len(blocked_elements) < 1:
                        self.logger.warning(
                            'Did not find any elements to block on detection ID {}'.format(detection.id))
                    for element in blocked_elements:
                        tag_to_set.append('VAE ID:{client_class}:{id}'.format(
                            client_class=third_party_client.__class__.__name__, id=element))
                    self.logger.info('Blocked detection ID {id} on client {client}'.format(
                        id=detection.id, client=third_party_client.__class__.__name__))
                    self.vectra_api_client.set_detection_tags(
                        detection_id=detection_id, tags=tag_to_set, append=True)
                    self.vectra_api_client.set_detection_note(detection_id=detection.id, note='Automatically blocked on {}'.format(
                        datetime.now().strftime('%d %b %Y at %H:%M:%S')))
                    self.logger.debug('Added Tags to detection')
                except HTTPException as e:
                    self.logger.error('Error encountered trying to block detection ID {}: {}'.format(
                        detection.id, str(e)))

    def unblock_detections(self, detections_to_unblock):
        for detection_id, detection in detections_to_unblock.items():
            for third_party_client in self.third_party_clients:
                try:
                    unblocked_elements = third_party_client.unblock_detection(
                        detection)
                    for element in unblocked_elements:
                        self.logger.debug(
                            'Unblocked element {}'.format(element))
                    self.logger.info('Unquaratained detection ID {id} on {client}'.format(
                        id=detection.id, client=third_party_client.__class__.__name__))
                    # Remove all tags set by this script from the detection.
                    # Sometimes a detection can have both a block and unblock tag, we need to correct this.
                    if 'block' in detection.tags:
                        self.logger.warning(
                            'detection ID {} is in no-block list but has a "block" tag. Removing tag..'.format(detection.id))
                        detection.tags.remove('block')
                    self.vectra_api_client.set_detection_tags(
                        detection_id=detection_id, tags=detection.tags, append=False)
                    self.logger.debug('Removed tags')
                except HTTPException as e:
                    self.logger.error('Error encountered trying to unblock detection ID {}: {}'.format(
                        detection.id, str(e)))


def main():
    def obtain_args():
        parser = argparse.ArgumentParser(description='Vectra Active Enforcement Framework ',
                                         prefix_chars='--', formatter_class=argparse.RawTextHelpFormatter,
                                         epilog='')
        parser.add_argument('--loop', default=False, action='store_true', help='Run in loop.  '
                                                                             'Required when ran as service.')
        parser.add_argument('--keyring', default=False, action='store_true', help='Utilize system\'s keyring for'
                                                                                'sensitive API keys.')
        return parser.parse_args()

    args = obtain_args()

    # define required clients
    t_client = test_client.TestClient()
    # pulse_nac_client = pulse_nac.PulseNACClient()
    # ise_client = ise.ISEClient()
    # bitdefender_client = bitdefender.BitdefenderClient()
    # amp_client = amp.AMPClient
    meraki_client = meraki.MerakiClient(use_keyring=args.keyring)
    if args.keyring:
        vectra_api_client = VectraClient(url=COGNITO_URL, token=keyring.get_password('VAE', 'Detect'))
    else:
        vectra_api_client = VectraClient(url=COGNITO_URL, token=COGNITO_TOKEN)
    # meraki_client = meraki.MerakiClient()
    vectra_api_client = VectraClient(url=COGNITO_URL, token=COGNITO_TOKEN)
    vae = VectraActiveEnforcement(
        third_party_clients=[t_client],
        vectra_api_client=vectra_api_client,
        block_host_tag=BLOCK_HOST_TAG,
        block_host_tc_score=BLOCK_HOST_THREAT_CERTAINTY,
        block_host_group_name=BLOCK_HOST_GROUP_NAME,
        block_host_detection_types=BLOCK_HOST_DETECTION_TYPES,
        block_host_detections_types_min_host_tc=BLOCK_HOST_DETECTION_TYPES_MIN_TC_SCORE,
        no_block_host_group_name=NO_BLOCK_HOST_GROUP_NAME,
        external_block_host_tc=EXTERNAL_BLOCK_HOST_TC,
        external_block_detection_types=EXTERNAL_BLOCK_DETECTION_TYPES,
        external_block_detection_tag=EXTERNAL_BLOCK_DETECTION_TAG,
    )

    def take_action():
        hosts_to_block, hosts_to_unblock = vae.get_hosts_to_block_unblock()
        vae.block_hosts(hosts_to_block)
        vae.unblock_hosts(hosts_to_unblock)

        detections_to_block, detections_to_unblock = vae.get_detections_to_block_unblock()
        vae.block_detections(detections_to_block)
        vae.unblock_detections(detections_to_unblock)

        logging.info('Run finished\n\n\n')

    if args.loop:
        while True:
            take_action()
            time.sleep(60 * SLEEP_MINUTES)
    else:
        take_action()


if __name__ == '__main__':
    main()
