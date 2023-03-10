import ipaddress
import re


class VectraHost:
    def __init__(self, host):
        self.id = host['id']
        self.name = host['name']
        self.ip = host['last_source']
        self.probable_owner = host['probable_owner']
        self.certainty = host['certainty']
        self.threat = host['threat']
        self.is_key_asset = host['key_asset']
        self.targets_key_asset = host['targets_key_asset']
        self.artifacts_types = self._get_artifact_types(host['host_artifact_set'])
        self.mac_addresses = self._get_host_mac_addresses(host['host_artifact_set'])
        self.vmware_vm_name = self._get_vmware_vm_name(host['host_artifact_set'])
        self.vmware_vm_uuid = self._get_vmware_vm_uuid(host['host_artifact_set'])
        self.aws_vm_uuid = self._get_aws_vm_uuid(host['host_artifact_set'])
        self.tags = self._get_external_tags(host['tags'])
        self.most_recent_note = host["note"]
        self.blocked_elements = self._get_blocked_elements(host['tags'])
        self._raw = host
    
    def get_full_name(self):
        if "windows_defender_name" in self.artifacts_types:
            return self._get_artifact_value("windows_defender_name")[0]
        if "dns" in self.artifacts_types:
            return self._get_artifact_value("dns")[0]
        if "rdns" in self.artifacts_types:
            return self._get_artifact_value("rdns")[0]
        if self._raw["ldap"]:
            if "dns_hostname" in self._raw["ldap"].keys():
                return self._raw["ldap"]["dns_hostname"][0]
        return self.name

    def _get_artifact_value(self, artifact_type):
        values = set()
        for artifact in self._raw["host_artifact_set"]:
            if artifact["type"] == artifact_type:
                values.add(artifact["value"])
        return list(values)

    def _get_artifact_types(self, artifact_set):
        artifact_keys = set()
        for artifact in artifact_set:
            artifact_keys.add(artifact['type'])
        return list(artifact_keys)

    def _get_host_mac_addresses(self, artifact_set):
        mac_addresses = set()
        for artifact in artifact_set:
            if artifact['type'] == 'mac':
                mac_addresses.add(artifact['value'])
        return list(mac_addresses)

    def _get_vmware_vm_name(self, artifact_set):
        for artifact in artifact_set:
            if artifact['type'] == 'vmachine_info':
                return artifact['value']
        return None

    def _get_vmware_vm_uuid(self, artifact_set):
        for artifact in artifact_set:
            if artifact['type'] == 'vm_uuid':
                return artifact['value']
        return None

    def _get_aws_vm_uuid(self, artifact_set):
        for artifact in artifact_set:
            if artifact['type'] == 'aws_vm_uuid':
                return artifact['value']
        return None

    def _get_blocked_elements(self, tags):
        blocked_elements = {}
        for tag in tags:
            if tag.startswith('VAE ID:'):
                # Tags are in the form "VAE ID:Client:ID"
                blocking_client = re.findall(':.*?:', tag)[0].replace(':','')
                id = tag[tag.find(blocking_client)+len(blocking_client)+1:]
                if blocking_client not in blocked_elements:
                    blocked_elements[blocking_client] = [id]
                else:
                    blocked_elements[blocking_client].append(id)
        return blocked_elements

    def _get_external_tags(self, tags):
        tags_to_keep = []
        for tag in tags:
            if not tag.startswith('VAE ID:') and not tag == 'VAE Blocked':
                tags_to_keep.append(tag)
        return tags_to_keep


class VectraDetection:
    def __init__(self, detection):
        self.id = detection['id']
        self.category = detection['category']
        self.detection_type = detection['detection_type']
        self.src = detection['src_ip']
        self.dst_ips = self._get_dst_ips(detection)
        self.dst_domains = self._get_dst_domains (detection)
        self.state = detection['state']
        self.c_score = detection['c_score']
        self.t_score = detection['t_score']
        self.targets_ka = detection['targets_key_asset']
        self.triage = detection['triage_rule_id']
        self.tags = self._get_external_tags(detection['tags'])
        self.blocked_elements = self._get_blocked_elements(detection['tags'])

    def _get_dst_ips(self, detection):
        dst_ips = set()
        for ip in detection['summary'].get('dst_ips', []):
            if not ipaddress.ip_address(ip).is_private:
                dst_ips.add(ip)
        return list(dst_ips)

    def _get_dst_domains(self, detection):
        dst_domains = set()
        for domain in detection['summary'].get('target_domains', []):
            dst_domains.add(domain)
        return list(dst_domains)

    def _get_blocked_elements(self, tags):
        blocked_elements = {}
        for tag in tags:
            if tag.startswith('VAE ID:'):
                # Tags are in the form "VAE ID:Client:ID"
                blocking_client = re.findall(':.*?:', tag)[0].replace(':','')
                id = tag[tag.find(blocking_client)+len(blocking_client)+1:]
                if blocking_client not in blocked_elements:
                    blocked_elements[blocking_client] = [id]
                else:
                    blocked_elements[blocking_client].append(id)
        return blocked_elements

    def _get_external_tags(self, tags):
        tags = []
        for tag in tags:
            if not tag.startswith('VAE ID:') and not tag == 'VAE Blocked':
                tags.append(tag)
        return tags
