# Address group to which to add internal IPs for blocking (E-W traffic).
INTERNAL_BLOCK_POLICY = 'Internal-Block'
# Address group to which to add external IPs for blocking (N-S traffic).
EXTERNAL_BLOCK_POLICY = 'External-Block'
# Create and populate a dict for each Firewall instance
FIREWALLS = [
    {
        'IP': '10.203.1.68',
        'PORT': 443,		
        'TOKEN': 'xy0z5bzgkgzjbQ7H4wkxrrG7thxdqH', 
        'VDOM': 'PROD',
		'VERIFY': False
    }
]