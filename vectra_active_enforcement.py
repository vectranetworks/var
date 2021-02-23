import logging
import requests
from vectra_client import VectraClient, HTTPException
from datetime import datetime
from typing import Union, Optional, Dict
from third_party_clients.fortinet.fortinet import FortiClient
from vectra_active_enforcement_consts import VectraHost, VectraDetection
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from config import (COGNITO_URL, COGNITO_TOKEN, BLOCK_HOST_TAG, UNBLOCK_HOST_TAG, 
    NO_BLOCK_HOST_GROUP_NAME, BLOCK_HOST_THREAT_CERTAINTY, BLOCK_HOST_DETECTION_TYPES_MIN_TC_SCORE,
    BLOCK_HOST_DETECTION_TYPES, EXTERNAL_BLOCK_HOST_TC,EXTERNAL_BLOCK_DETECTION_TAG, 
    EXTERNAL_BLOCK_DETECTION_TYPES, EXTERNAL_UNBLOCK_DETECTION_TAG)


logging.basicConfig(level=logging.INFO)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


HostDict = Dict[str, VectraHost] 
DetectionDict = Dict[str, VectraDetection] 


class VectraActiveEnforcement(object):
    
    def __init__(self, 
            fw_clients: list, 
            vectra_api_client: VectraClient, 
            block_host_tag: Optional[str],
            block_host_tc_score: tuple, 
            block_host_detection_types: list,
            block_host_detections_types_min_host_tc: tuple,
            unblock_host_tag: Optional[str], 
            no_block_host_group_name: Optional[str],
            external_block_host_tc: tuple,
            external_block_detection_types:list,
            external_block_detection_tag: Optional[str],
            external_unblock_detection_tag: Optional[str]
        ):
        # Generic setup
        self.logger = logging.getLogger()
        self.fw_clients = fw_clients
        self.vectra_api_client = vectra_api_client
        # Internal (un)blocking variables  
        self.block_host_tag = block_host_tag
        self.block_host_tc_score = block_host_tc_score
        self.block_host_detection_types = block_host_detection_types
        self.block_host_detections_types_min_host_tc = block_host_detections_types_min_host_tc
        self.unblock_host_tag = unblock_host_tag
        self.no_block_host_group_name = no_block_host_group_name
        # External (un)blocking variables
        self.external_block_host_tc = external_block_host_tc
        self.external_block_detection_types = external_block_detection_types
        self.external_block_detection_tag = external_block_detection_tag
        self.external_unblock_detection_tag = external_unblock_detection_tag

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
        no_block_hosts = self.vectra_api_client.get_noblock_hosts(no_block_group=self.no_block_host_group_name, no_block_tag=self.unblock_host_tag)
        # Get a dict of hosts to block
        matching_hosts = self.vectra_api_client.get_hosts_to_block(
                block_tag=self.block_host_tag, 
                min_tc_score=self.block_host_tc_score,
                block_host_detection_types=self.block_host_detection_types,
                block_host_detections_types_min_host_tc=self.block_host_detections_types_min_host_tc
            )
        # Get a dict of hosts already blocked
        blocked_hosts = self.vectra_api_client.get_tagged_hosts(tag='VAE Blocked')
        self.logger.info('Found {} already blocked hosts on Vectra'.format(str(len(blocked_hosts.keys()))))
        # Find blocked hosts that should be unblocked
        hosts_wrongly_blocked = self._get_dict_keys_intersect(blocked_hosts, no_block_hosts)
        self.logger.info('Found {} blocked hosts that are now part of the no-block lists'.format(str(len(hosts_wrongly_blocked.keys()))))
        # Compute hosts that should be blocked
        hosts_to_block = self._get_dict_keys_relative_complement(matching_hosts, blocked_hosts)
        # Take into account exclusions
        hosts_to_block = self._get_dict_keys_relative_complement(hosts_to_block, no_block_hosts)
        self.logger.info('Found {} hosts that need to be blocked'.format(str(len(hosts_to_block.keys()))))
        # Compute hosts that should be unblocked
        hosts_to_unblock = self._get_dict_keys_relative_complement(blocked_hosts, matching_hosts)
        # Add wrongly blocked hosts
        hosts_to_unblock  = {**hosts_to_unblock, **hosts_wrongly_blocked}
        self.logger.info('Found {} hosts that need to be unblocked'.format(str(len(hosts_to_unblock.keys()))))
        return hosts_to_block, hosts_to_unblock

    def get_detections_to_block_unblock(self):
        # Get a list of all detections that should be unblocked or never blocked
        no_block_detections = self.vectra_api_client.get_noblock_detections(no_block_group=self.no_block_host_group_name, no_block_tag=self.external_unblock_detection_tag)
        # Get a dict of detections to block
        detections_to_block = self.vectra_api_client.get_detections_to_block(
            block_tag=self.external_block_detection_tag, 
            detection_types_to_block=self.external_block_detection_types,
            min_host_tc_score=self.external_block_host_tc
            )
        # Get a dict of detections already blocked
        blocked_detections = self.vectra_api_client.get_tagged_detections(tag='VAE Blocked')
        self.logger.info('Found {} already blocked detections on Vectra'.format(str(len(blocked_detections.keys()))))
        # Find blocked detections that should be unblocked
        detections_wrongly_blocked = self._get_dict_keys_intersect(blocked_detections, no_block_detections)
        self.logger.info('Found {} blocked detections that are now part of the no-block lists'.format(str(len(detections_wrongly_blocked.keys()))))
        # Compute detections that should be blocked
        detections_to_block = self._get_dict_keys_relative_complement(detections_to_block, blocked_detections)
        # Take into account exclusions
        detections_to_block = self._get_dict_keys_relative_complement(detections_to_block, no_block_detections)
        self.logger.info('Found {} detections that need to be blocked'.format(str(len(detections_to_block.keys()))))
        # Compute detections that should be unblocked
        detections_to_unblock = self._get_dict_keys_relative_complement(blocked_detections, detections_to_block)
        # Add wrongly blocked detections
        detections_to_unblock  = {**detections_to_unblock, **detections_wrongly_blocked}
        self.logger.info('Found {} detections that need to be unblocked'.format(str(len(detections_to_unblock.keys()))))
        return detections_to_block, detections_to_unblock

    def block_hosts(self, hosts_to_block):
        for host_id, host in hosts_to_block.items():
            for firewall in self.fw_clients:
                try:
                    # Quarantaine endpoint
                    host = firewall.block_host(host=host)
                    self.logger.info('Blocked host {} on firewall'.format(host.name))
                    # Set a "VAE Blocked" to set the host as being blocked and registed what elements were blocked in separate tags
                    tag_to_set = ['VAE Blocked']
                    if len(host.blocked_elements) < 1:
                        raise HTTPException('No elements blocked by FW')
                    for element in host.blocked_elements:
                        tag_to_set.append('VAE ID: {}'.format(element))
                    self.vectra_api_client.set_host_tags(host_id=host_id, tags=tag_to_set, append=True)
                    self.vectra_api_client.set_host_note(host_id=host.id, note='Automatically blocked on {}'.format(datetime.now().strftime('%d %b %Y at %H:%M:%S')), append=False)
                    self.logger.debug('Added Tags to host')
                except HTTPException as e:
                    self.logger.error('Error encountered trying to block Host ID {}: {}'.format(host.id, str(e)))

    def unblock_hosts(self, hosts_to_unblock):
        for host_id, host in hosts_to_unblock.items():
            if len(host.blocked_elements) < 1:
                self.logger.error('Could not find what was blocked on host {}'.format(host.name))
                continue
            for firewall in self.fw_clients:
                try:
                    host = firewall.unblock_host(host)
                    self.logger.info('Unquaratained host {}'.format(host.name))
                    # Remove all tags set by this script from the host.
                    # Sometimes a host can have both a block and unblock tag, we need to correct this. 
                    if 'block' in host.tags:
                        self.logger.warning('Host {} is in no-block list but has a "block" tag. Removing tag..'.format(host['name']))
                        host.tags.remove('block')
                    self.vectra_api_client.set_host_tags(host_id=host_id, tags=host.tags, append=False)
                    self.logger.debug('Removed tags')
                except HTTPException as e:
                    self.logger.error('Error encountered trying to unblock Host ID{}: {}'.format(host.id, str(e)))


    def block_detections(self, detections_to_block):
        for detection_id, detection in detections_to_block.items():
            for firewall in self.fw_clients:
                try:
                    # Quarantaine endpoint
                    detection = firewall.block_detection(detection=detection)
                    self.logger.info('Blocked detection {} on firewall'.format(detection.name))
                    # Set a "VAE Blocked" to set the detection as being blocked and registed what elements were blocked in separate tags
                    tag_to_set = ['VAE Blocked']
                    if len(detection.blocked_elements) < 1:
                        raise HTTPException('No elements blocked by FW')
                    for element in detection.blocked_elements:
                        tag_to_set.append('VAE ID: {}'.format(element))
                    self.vectra_api_client.set_detection_tags(detection_id=detection_id, tags=tag_to_set, append=True)
                    self.vectra_api_client.set_detection_note(detection_id=detection.id, note='Automatically blocked on {}'.format(datetime.now().strftime('%d %b %Y at %H:%M:%S')), append=False)
                    self.logger.debug('Added Tags to detection')
                except HTTPException as e:
                    self.logger.error('Error encountered trying to block detection ID {}: {}'.format(detection.id, str(e)))

    def unblock_detections(self, detections_to_unblock):
        for detection_id, detection in detections_to_unblock.items():
            if len(detection.blocked_elements) < 1:
                self.logger.error('Could not find what was blocked on detection {}'.format(detection.name))
                continue
            for firewall in self.fw_clients:
                try:
                    detection = firewall.unblock_detection(detection)
                    self.logger.info('Unquaratained detection {}'.format(detection.name))
                    # Remove all tags set by this script from the detection.
                    # Sometimes a detection can have both a block and unblock tag, we need to correct this. 
                    if 'block' in detection.tags:
                        self.logger.warning('detection {} is in no-block list but has a "block" tag. Removing tag..'.format(detection['name']))
                        detection.tags.remove('block')
                    self.vectra_api_client.set_detection_tags(detection_id=detection_id, tags=detection.tags, append=False)
                    self.logger.debug('Removed tags')
                except HTTPException as e:
                    self.logger.error('Error encountered trying to unblock detection ID {}: {}'.format(detection.id, str(e)))

def main():
    logging.basicConfig(level=logging.INFO)
    fortinet_client = FortiClient()
    vectra_api_client = VectraClient(url=COGNITO_URL, token=COGNITO_TOKEN)
    vae = VectraActiveEnforcement(
            fw_clients = [fortinet_client], 
            vectra_api_client = vectra_api_client,
            block_host_tag = BLOCK_HOST_TAG,
            block_host_tc_score = BLOCK_HOST_THREAT_CERTAINTY, 
            block_host_detection_types = BLOCK_HOST_DETECTION_TYPES,
            block_host_detections_types_min_host_tc = BLOCK_HOST_DETECTION_TYPES_MIN_TC_SCORE,
            unblock_host_tag = UNBLOCK_HOST_TAG, 
            no_block_host_group_name = NO_BLOCK_HOST_GROUP_NAME,
            external_block_host_tc = EXTERNAL_BLOCK_HOST_TC,
            external_block_detection_types = EXTERNAL_BLOCK_DETECTION_TYPES,
            external_block_detection_tag = EXTERNAL_BLOCK_DETECTION_TAG,
            external_unblock_detection_tag = EXTERNAL_UNBLOCK_DETECTION_TAG
        )

    #hosts_to_block, hosts_to_unblock = vae.get_hosts_to_block_unblock()
    detections_to_block, detections_to_unblock = vae.get_detections_to_block_unblock()
    #vae.block_hosts(hosts_to_block)
    #vae.unblock_hosts(hosts_to_unblock)


if __name__ == '__main__':
    main()
