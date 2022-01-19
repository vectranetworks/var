# Introduction

This third party client implement automated blocking by integrating with FortiOS. The script can either connect to a centralized Fortinet management appliance, or to every individual firewall of the environment (which will of couse be less efficient).

The script will update two address groups, which **need to be created manually** prior to thhe first execution of the script on the firewall. 

One of those address groups is meant for containing internal IP address of hosts, while the other is for containing external IPs found on detections with an external component. 

The internal address group will only be populated if host-based blocking is enabled, while the external address group will only be populated if detection-based blocking is enabled. 

# Configuration

All confuguration is done in the [fortinet_config.py](./fortinet_config.py) file. Normally you shouldn't have to edit anything elsewhere. 

The internal and external address group names are freely configurable, the corresponding variables are _INTERNAL_ADDRESS_GROUP_ and _EXTERNAL_ADDRESS_GROUP_ respectively. 

The _FIREWALLS_ variable is a list of all firewalls the script must connect to to do the integration. If working with a centralized management appliance, only one must be configured. 


# Getting a Fortinet API token

* Step 1: Determine your Source Address: The source address is needed to ensure the API token can only be used from trusted hosts. As the API calls will come from the middleware server, you need to determine its IP address, running for instance ```bash ip addr```. 

* Step 2: Create an Administrator profile: you need to create a profile that only has Read/Write access to the firewall address permission group. On the FortiGate GUI, select System > Admin Profiles > Create New. Populate the fields according to your environment.

* Step 3: Create the REST API Admin: On the FortiGate GUI, select System > Administrators > Create New > REST API Admin.

   The Trusted Host must be specified to ensure that your local host can reach the FortiGate. For example, to restrict requests as coming from only 10.20.100.99, enter 10.20.100.99/32. The Trusted Host is created from the Source Address obtained in Step 1: Determine your Source Address.
   
   In Administrator Profile field, select profile from Step2. Note: If you want to configure VDOM or resources related to administrator user permissions, you need to set the field with the System predefined Administrator Profile super_admin by CLI.
   
   Click OK and an API token will be generated.
   
   Make note of the API token as it is only shown once and cannot be retrieved. It will be needed for the rest of the tutorial.
   
   Click Close to complete creation of the REST API Admin.

