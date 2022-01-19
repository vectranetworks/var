# Documentation

To see documentation relative to specific third party integrations, navigate to the relevant folder. 

# Third party integration abstract class

The [third_party_interface.py](./third_party_interface.py) file contains the definition of the abstract class which every third party integration client must implement. 

This interface defines 4 methods that must be reimplemented:
1. block_host()
2. unblock_host()
3. block_detection()
4. unblock_detection()

Both host based methods will receive a VectraHost() instance as argument, as defined in [vectra_active_enforcement_consts.py](../vectra_active_enforcement_consts.py). 

Both detection based methods will receive an VectraDetection instance as argument, as defined in [vectra_active_enforcement_consts.py](../vectra_active_enforcement_consts.py). 