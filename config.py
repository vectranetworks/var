### GENERAL SETUP
# Vectra brain API access.
COGNITO_URL = 'https://vectra.maxonmotor.com/'
COGNITO_TOKEN = 'c5a6eb331c9c94a99d335213faf595e68f90b25e'

### INTERNAL IP BLOCKING
# Tag that will cause a host to be blocked.
BLOCK_HOST_TAG = 'block'
# Tag to unblock a host, AND prevent it from being blocked again as long as present.
UNBLOCK_HOST_TAG = 'noblock'
# Host group for which member will NEVER be blocked.
NO_BLOCK_HOST_GROUP_NAME = 'NoBlock'
# Host groupfor which all members will be blocked
BLOCK_HOST_GROUP_NAME = 'maxon - Clearpass Client blocking'
# Threshold threat/certainty score for automatically blocking host.
# The middle argument can be 'and' or 'or', defining how the threshold conditions are read
BLOCK_HOST_THREAT_CERTAINTY = (100, 'and', 100)
# List of detection types that when present will cause host to be blocked.
# The second argument enforces a threat/cetainty threshold for hosts with those detection types on.
BLOCK_HOST_DETECTION_TYPES = []
BLOCK_HOST_DETECTION_TYPES_MIN_TC_SCORE = (100, 'or', 100)

### EXTERNAL IP BlOCKING
# Host threat/certainty score when reached will get all detections on the host.
# All external IPs in those detections will then be blocked. 
# The middle argument can be 'and' or 'or', defining how the threshold conditions are read
EXTERNAL_BLOCK_HOST_TC = (100, 'and', 100)
# Tag to block external IPs present in detection.
EXTERNAL_BLOCK_DETECTION_TAG = 'block'
# Detection types for which we will block all external IPs present on those.
# E.g. "Ransomware File Activity,Shell Knocker"
EXTERNAL_BLOCK_DETECTION_TYPES = []
# Tag to unblock a detection, AND prevent it from being blocked again as long as present.
EXTERNAL_UNBLOCK_DETECTION_TAG = 'noblock'