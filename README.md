# Introduction
This is a framework meant to allow for easy integration of any third-party security vendor. 

Based on various input parameters (detaisl below), the script returns a list of Host/Detections to be bocked/unblocked. 

The code defines an abstract class which third-party clients must extend, which allows for easy integration with the workflow implemented by the base script. 

# Workflow
On the Vectra side, the script allows multiple parameters based on which Host/Detections will be sent to the third-party client to be blocked/unblocked. 

Those paramters are defined in the "config.py" file, and are the following:

## Selecting Hosts for blocking/unblocking
