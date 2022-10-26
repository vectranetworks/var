import ipaddress
import logging
import requests
import urllib.parse
import xml.etree.ElementTree as ET
from urllib3.exceptions import InsecureRequestWarning
from third_party_clients.sophos.sophos_config import ADDRESS, IS_ENCRYPTED, PASSWORD, PORT, USERNAME, BLOCK_LIST_IPHOST_NAME
from third_party_clients.third_party_interface import ThirdPartyInterface
from vectra_active_enforcement_consts import VectraHost

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class SophosClient(ThirdPartyInterface):
    def __init__(self):
        self.logger = logging.getLogger()
        self.baseurl = f"https://{ADDRESS}:{PORT}/webconsole/APIController?reqxml="
        self.login_xml = f"<Login><Username>{USERNAME}</Username><Password passwordform=\"{'encrypted' if IS_ENCRYPTED else 'plain'}\">{PASSWORD}</Password></Login>"
        self._login_check()
        # Instantiate parent class
        ThirdPartyInterface.__init__ (self)

    def block_host(self, host) -> list[str]:
        return self._block_ip(ip=host.ip)

    def unblock_host(self, host) -> list[str]:
        return self._unblock_ip(ip=host.ip)
    
    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn("Sophos client does not implement detection-based blocking")
        return []

    def unblock_detection(self, detection):
        # this client only implements Host-based blocking
        return []

    def _make_api_call(self, request_xml: str) -> requests.Response:
        full_reqxml = f"<Request>{self.login_xml}{request_xml}</Request>"
        self.logger.debug(f"Making request: {self.baseurl + full_reqxml}")
        reqxml_encoded = urllib.parse.quote_plus(full_reqxml)
        url = self.baseurl + reqxml_encoded
        response = requests.get(url=url, verify=False)
        response.raise_for_status()
        return response

    def _login_check(self):
        r = self._make_api_call("")
        xml = ET.fromstring(r.text)
        if xml.find('Login').find('status').text == "Authentication Successful":
            self.logger.info("Sophos Firewall Integartion API Login Check Successful")
        else:
            self.logger.error("Sophos Firewall Integartion API Login Check Failed. Please check credentials.")
            exit()

    def _get_blocked_ips(self) -> list[str]:
        r = self._make_api_call(f"<Get><IPHost><Filter><key name=\"Name\" criteria=\"=\">{BLOCK_LIST_IPHOST_NAME}</key></Filter></IPHost></Get>")
        xml = ET.fromstring(r.text)
        iphosts = xml.findall('IPHost')
        if len(iphosts) > 1:
            self.logger.warn(f"Multiple IPHosts with Name equaling \"{BLOCK_LIST_IPHOST_NAME}\" found. Using first one. Please verify firewall is setup according to documentation.")
        elif len(iphosts) == 0:
            self.logger.error(f"No IPHost with Name equaling \"{BLOCK_LIST_IPHOST_NAME}\" found. Please verify firewall is setup according to documentation.")
            exit()
        blocked_ips = iphosts[0].find('ListOfIPAddresses').text.split(sep=',')
        self.logger.debug(f"Retrieved currently blocked ips: {blocked_ips}")
        return blocked_ips

    def _update_blocked_ips(self, ips_to_block: list[str]) -> bool:
        ip_csv = ','.join(ips_to_block)
        r = self._make_api_call(f"<Set operation=\"update\"><IPHost><Name>{BLOCK_LIST_IPHOST_NAME}</Name><IPFamily>IPv4</IPFamily><HostType>IPList</HostType><ListOfIPAddresses>{ip_csv}</ListOfIPAddresses></IPHost></Set>")
        xml = ET.fromstring(r.text)
        status = xml.find('IPHost').find('Status')
        status_code = status.attrib['code']
        status_msg = status.text
        if status_code != '200':
            self.logger.error(f"Error updating IP list of IPHost \"{BLOCK_LIST_IPHOST_NAME}\". (Status Code: {status_code} - Message: {status_msg})")
            return False
        return True


    def _block_ip(self, ip: str) -> list[str]:
        if self._validate_ip_address(ip):
            blocked_ips = self._get_blocked_ips()
            if ip not in blocked_ips:
                blocked_ips.append(ip)
                if self._update_blocked_ips(blocked_ips):
                    return [ip]
        return []

    def _unblock_ip(self, ip: str) -> list[str]:
        if self._validate_ip_address(ip):
            blocked_IPs = self._get_blocked_ips()
            if ip in blocked_IPs:
                blocked_IPs.remove(ip)
                if self._update_blocked_ips(blocked_IPs):
                    return [ip]
        return []

    def _validate_ip_address(self, ip: str):
        try:
            _ = ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False