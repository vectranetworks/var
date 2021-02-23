import logging
import vat.vectra as vectra


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
        body = 'Status code: {code} - {detail}'.format(code=str(response.status_code), detail=detail)
        super().__init__(body)


class VectraClient(vectra.VectraClientV2_2):

    def __init__(self, url=None, token=None, verify=False):
        """
        Initialize Vectra client
        :param url: IP or hostname of Vectra brain - required
        :param token: API token for authentication - required
        :param verify: verify SSL - optional
        """
        vectra.VectraClientV2_1.__init__(self, url=url, token=token, verify=verify)
        self.logger = logging.getLogger('VectraClient')

    def get_hosts_in_group(self, group_name: str) -> HostDict:
        """
        Get a dictionnary of all hosts present in a group. 
        :param group_name: name of the group for which to return the hosts
        :rtype: HostDict
        """
        hosts = {}
        r = self.get_all_groups(name=group_name)
        for page in r:
            for group in page.json()['results']:
                for member in group['members']:
                    host = self.get_host_by_id(host_id=member['id']).json()
                    if host['id'] not in hosts:
                        hosts[host['id']] = VectraHost(host)
        return hosts

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
            self.logger.error('Invalid Threat/Certainty tuple provided in the BLOCK_HOST_THREAT_CERTAINTY parameter')
            exit(99)

        if condition == 'and':
            r = self.get_all_hosts(threat_gte=threat_gte, certainty_gte=certainty_gte, all=True)
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
            self.logger.error('Invalid Threat/Certainty tuple provided in the BLOCK_HOST_THREAT_CERTAINTY parameter')
            exit(99)

        detections = self.get_detections_by_type(detection_types=detection_types)
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

    def get_noblock_hosts(self, no_block_group: Optional[str] = None, no_block_tag: Optional[str] = None) -> HostDict:
        """
        Get all host IDs which should not be blocked
        :param no_block_group: group name containing hosts which should never be blocked - optional
        :param no_block_tag: tag defining host to never block or unblock - optional
        :rtype: HostDict
        """
        no_block_tagged_hosts = self.get_tagged_hosts(tag=no_block_tag) if no_block_tag else {}
        no_block_group_hosts = self.get_hosts_in_group(group_name=no_block_group) if no_block_group else {}
        return {**no_block_tagged_hosts, **no_block_group_hosts}

    def get_hosts_to_block(self, 
            block_tag: Optional[str] = None, 
            min_tc_score: Optional[tuple] = None, 
            block_host_detection_types: list = [], 
            block_host_detections_types_min_host_tc: tuple = (0,'and',0)
            ) -> HostDict:
        """
        Get all host IDs which should be blocked given the parameters. 
        :param block_tag: tag defining hosts that need to be blocked - optional
        :param min_tc_score: tuple of (threat, certainty) to query hosts exceeding this threshold - optional
        :param block_host_detection_types: list of detections types which if present on a host will cause the host to be blocked - optional
        :rtype: HostDict
        """
        tagged_hosts = self.get_tagged_hosts(tag=block_tag) if block_tag else {}
        scored_hosts = self.get_scored_hosts(tc_tuple = min_tc_score) if isinstance(min_tc_score, tuple) else {}
        hosts_with_detection_types = self.get_hosts_with_detection_types(block_host_detection_types, block_host_detections_types_min_host_tc) if block_host_detection_types else {}
        return {**tagged_hosts, **scored_hosts, **hosts_with_detection_types}

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
                if tag in detection['tags']: # for some reason the API does substring matching, so we check
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
            r = self.get_all_detections(detection_type=detection_types, state='active')
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
        host = self.get_host_by_id(host_id=host_id, fields='detection_set').json()
        for detection in host.get('detection_set', []):
            detection_ids.add(detection.rsplit('/',1)[1])
        # Get individual detections
        detections = {}
        for detection_id in detection_ids:
            r = self.get_detection_by_id(detection_id=detection_id)
            detection = r.json()
            # Ignore info detections
            if detection.get('category') != 'INFO':
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
                    detections.update(self.get_detections_on_host(host_id=member['id']))
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

    def get_noblock_detections(self, no_block_group: Optional[str] = None, no_block_tag: Optional[str] = None) -> DetectionDict:
        """
        Get a dict of all detection IDs which should not be blocked given the parameters. 
        :param no_block_group: name of the host group whose member detections should never be blocked - optional
        :param no_block_tag: tag defning detections which should not be blocked or unblocked - optional
        :rtype: DetectionDict
        """
        no_block_tagged_detections = self.get_tagged_detections(tag=no_block_tag) if no_block_tag else {}
        no_block_group_detections = self.get_detections_on_hosts_in_group(group_name=no_block_group) if no_block_group else {}
        return {**no_block_tagged_detections, **no_block_group_detections}

    def get_detections_to_block(self, block_tag: Optional[str] = None, detection_types_to_block: Optional[list] = None, min_host_tc_score: Optional[tuple] = None) -> DetectionDict:
        """
        Get a dict of all detection IDs which should be blocked given the parameters. 
        :param block_tag: tag defning detections which should be blocked or unblocked - optional
        :param detection_types_to_block: list of detection types to block, regardless of score
        :param min_host_tc_score: tuple (int, int) of min host threat/certainty score for which,\
            if exceeded to block all detections on host. 
        :rtype: DetectionDict
        """
        tagged_detections = self.get_tagged_detections(tag=block_tag) if block_tag else {}
        typed_detections = self.get_detections_by_type(detection_types=detection_types_to_block) if detection_types_to_block else {}
        detections_of_scored_hosts = self.get_detections_on_scored_host(min_host_tc_score=min_host_tc_score) if min_host_tc_score else {}
        return {**tagged_detections, **typed_detections, **detections_of_scored_hosts}

