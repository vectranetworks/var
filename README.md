# Introduction
This is a framework meant to allow for easy integration of any third-party security vendor. 

Based on various input parameters (detaisl below), the script returns a list of Host/Detections to be bocked/unblocked. 

The code defines an [abstract class](./third_party_clients/third_party_interface.py) which third-party clients must extend, which allows for easy integration with the workflow implemented by the base script. 

Since adding a new third party integration only requires to extend that class, I'd encourage to use this framework for any new integrations being built. 


# Third party integrations

Currently, the following third party integrations are implemented:
1. Bitdefender
2. Cisco ISE
3. ClearPass
4. Endgame
5. Fortinet firewalls (FortiOS)
6. Cisco Meraki
7. Palo Alto Network firewalls (Panorama or not)
8. Pulse Secure NAC
9. Sophos Firewall
10. Trendmicro Apex One
11. VMWare vSphere
12. Windows (direct PowerShell commands to shutdown host)

Integration-specific documentation can be found in the [relevant folders](./third_party_clients/) of the third party integrations. 


# Workflow

The script supports both host based blocking, and detection based blocking. Parameters defining what detections/host get blocked are defined in the [config.py](./config.py) file.


# Getting a Vectra API token. 

You will need to provide a Vectra API token within the [config.py](./config.py) file. To create a token, login into Vectra, go to "My Profile" and click to create an API token. 

Vectra API tokens will be linked ot the user that created them, and inherit the rights of that user. Any actions done using that API token will also show under the same username in the audit logs. 

YOu may want to create a separate user for the API integration for audit purposes, and only give it fine-grained RBAC rights. For the integration to work, the user will need:
* Read access to Hosts
* Read access to Detections
* Read access to "Manage - Groups"
* Read/Write access to tags
* Read/Write access to Notes & Other User's Notes


## Host-based blocking

The goal of host-based blocking is identyfying internal host who need to be prevented from being able to further communicate internally and/or externally. The blocking will happen on host psecific attributes, such as for instance the internal IP address, the MAC address or the hostname. 

There are mutliple parameters within the [config.py](./config.py) file which define how hosts are bein selected for blocking:

1. BLOCK_HOST_TAG: defines a tag that when set on a host will cause that host to be blocked.
2. BLOCK_HOST_GROUP_NAME: defines a group name, where all members of that group will be blocked. That group need to be created manually on the Cognito UI, it will not be created by the script. 
3. BLOCK_HOST_THREAT_CERTAINTY: defines a threat and certainty score threshold, above which host will get blocked. The middle variable can be either _and_ or _or_, defining how the threat and certainty conditions are threated. 
4. BLOCK_HOST_DETECTION_TYPES: this is a list containing specific detection types, which when present on a host will cause that host to be blocked. Using the _BLOCK_HOST_DETECTION_TYPES_MIN_TC_SCORE_ variable, it is possible to define a minimum threat/certainty score for those detections to cause blocking of the host. 

Besides this, the _NO_BLOCK_HOST_GROUP_NAME_ Defines a group name from which all members will never be blocked. Users need to create that group themselves, it is not created automatically by the script. 

**Important:** when blocking conditions are no longer fulfilled for a host, either because the blocking tag was removed, its score decreased, group membership was revoked, or the specific detection types causing blocking were fixed, the host will be automatically unblocked by the script on the next run. 

## Detection-based blocking

The goal of detection-based blocking is identifying detection containing external components (IP or domain), which can then be blacklisted on various security tools to prevent communication towards those from any internal machine. 

Most internal-focused third party clients, such as NACs or endpoints will not implement detection-based blocking, as they are not able to block public IPs/domains. This is mainly relevant for Firewall specific third party clients. Nevertheless, using detection based blocking with a mix of clients supporting it and not is not an issue, but will cause warnings to be logged when executing the script. 

Since this usually will block the IP/domain for the whoel environment, **extreme care is advised**, as in the case of false-positives it can have a large impact on the network. 

There are mutliple parameters within the [config.py](./config.py) file which define how detections are bein selected for blocking:

1. EXTERNAL_BLOCK_HOST_TC: defines host threat/certainty score above which all detections present on that host will get marked for blocking (or at least any external component present in those detections). 
2. EXTERNAL_BLOCK_DETECTION_TAG: defines a tag that when set on a detection will cause all external components of that detection to be blocked. 
3. EXTERNAL_BLOCK_DETECTION_TYPES: this is a list containing specific detection types, which will always have their external components automatically blocked. Any valid detection type will be accepted by the script, but it only makes sense for detections with an external component, thus Botnet, Command&Control or Exfil detections. 


# Configuring the Third-Party clients used

Users need to configure which third-party clients they indend the script to use, and instantiate those. This configuration needs to be done directly in the _vectra_active_enforcement.py_ file. 

By default, all available clients are imported into the script, so there's no specific need for adding import statements. 

The whole configuration happens in the _main()_ function. 

## Instantiating the clients

On top of the main function, by default a TestClient() is instantiated. Here we'll need to create one instance of each required client. 

For instance, if we're using the Fortinet client, we'd create something like this:
```python
forti_client = fortinet.FortiClient()
```

## Passing the third party client instances to the script

Once all required third party clients have been instantiated, they need to be passed to the script for it to know with which clients to work. 

This is done in the instantiation call of the _VectraActiveEnforcement()_ class. Specifically, all third party client instances we want to use need to be passed in the list argument _third_party_clients[]_.

If for example we want to instantiate a PAN client and a VMWare clients, it would look like follows:

```python
# Instantiate the clients here
pan_client = pan.PANClient()
vmware_client = vmware.VMWareClient()
vectra_api_client = VectraClient(url=COGNITO_URL, token=COGNITO_TOKEN)
vae = VectraActiveEnforcement(
        third_party_clients = [pan_client, vmware_client], # Add the clients to this list 
        vectra_api_client = vectra_api_client,
```

## Selecting what block types to run

Users can also configure if they want to run only host-based blocking, detection-based blocking or both. 

If one type is not desired, you can comment out the corresponding code blocks:

```python
# Those 3 lines handle host-based blocking; comment them out if you don't want it
hosts_to_block, hosts_to_unblock = vae.get_hosts_to_block_unblock()
vae.block_hosts(hosts_to_block)
vae.unblock_hosts(hosts_to_unblock)

# Those 3 lines handle detection-based blocking; comment them out if you don't want it
detections_to_block, detections_to_unblock = vae.get_detections_to_block_unblock()
vae.block_detections(detections_to_block)
vae.unblock_detections(detections_to_unblock)
```

## Running the script
The script can be run manually, via a cron job, or as a service.  If running as a service, specify the `--loop`
flag to run the script in a continuous loop with the pause time configured in the `config.py` file's variable 
`SLEEP_MINUTES`.
### Additional options
#### Keying
Modules may be modified to utilize API keys or credentials stored in the local system's keying.  Specifying
the `--keyring` flag will enable this feature for the supported modules.
#### Monitoring for IP changes
Modules may support attempting to re-block a host (re-grooming) if that host's IP has changed since it was originall
blocked.  To enable re-grooming for supported modules specify the `--groom` flag.