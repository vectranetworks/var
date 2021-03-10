# Group to which to add internal IPs for blocking.
INTERNAL_BLOCK_POLICY = 'G-ECCH-NoInternet'
# Group to which to add external IPs for blocking.
EXTERNAL_BLOCK_POLICY = '_G-EMS-Block'
# Create and populate a dict for each Firewall instance
FIREWALLS = [
    {
        #SD01022
        'IP': '10.203.1.68',
        'PORT': 443,		
        'TOKEN': 'xy0z5bzgkgzjbQ7H4wkxrrG7thxdqH', 
        'VDOM': 'PROD',
		'VERIFY': False
    }
]