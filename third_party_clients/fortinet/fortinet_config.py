# Group to which to add internal IPs for blocking.
INTERNAL_BLOCK_POLICY = 'vectra_internal_block'
# Group to which to add external IPs for blocking.
EXTERNAL_BLOCK_POLICY = 'vectra_external_block'
# Create and populate a dict for each Firewall instance
FIREWALLS = [
    {
        'IP': '1.2.3.4', 
        'USER': 'admin', 
        'PASS': '1234',
        'VDOM': 'root'
    }
]