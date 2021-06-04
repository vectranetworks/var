### GENERAL SETUP
# Vectra brain API access.
COGNITO_URL = 'https://demo.vectra.io'
COGNITO_TOKEN = '070d8c3ef9d310dad630de294af8997a16b01908'
LOG_TO_FILE = False
LOG_FILE = 'vae.log'

### INTERNAL IP BLOCKING
# Tag that will cause a host to be blocked; remove the tag to unblock the host
BLOCK_HOST_TAG = 'block'
# Host group for which member will NEVER be blocked.
NO_BLOCK_HOST_GROUP_NAME = 'NoBlock'
# Host groupfor which all members will be blocked
BLOCK_HOST_GROUP_NAME = 'Block'
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
# Tag to block external IPs present in detection; remove the tag to unblock the detection.
EXTERNAL_BLOCK_DETECTION_TAG = 'block'
# Detection types for which we will block all external IPs present on those.
# E.g. "External Remote Access, Data Smuggler"
EXTERNAL_BLOCK_DETECTION_TYPES = []