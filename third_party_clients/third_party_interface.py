import abc
from abc import ABCMeta
from vectra_active_enforcement_consts import VectraHost, VectraDetection


class ThirdPartyInterface(metaclass=abc.ABCMeta):
    @classmethod
    def __subclasshook__(cls, subclass):
        return (hasattr(subclass, 'block_host') and 
                callable(subclass.block_host) and
                hasattr(subclass, 'unblock_host') and 
                callable(subclass.unblock_host) and
                hasattr(subclass, 'groom_host') and
                callable(subclass.groom_host) and
                hasattr(subclass, 'block_detection') and 
                callable(subclass.block_detection) and  
                hasattr(subclass, 'unblock_detection') and
                callable(subclass.unblock_detection) or
                NotImplemented)

    def __init__(self):
        pass

    @abc.abstractmethod
    def block_host(self, host: VectraHost) -> list:
        """
        Block a VectraHost instance on the corresponding FW/NAC
        :rtype: list of all elements that were blocked
        """
        raise NotImplementedError

    @abc.abstractmethod
    def unblock_host(self, host: VectraHost) -> list:
        """
        Unlock a VectraHost instance on the corresponding FW/NAC
        :rtype: list of all elements that were unblocked
        """
        raise NotImplementedError

    @abc.abstractmethod
    def groom_host(self, host: VectraHost) -> dict:
        """
        Determine if a VectraHost instance needs to be blocked or unblocked.
        :rtype: dictionary of all elements that require blocking or unblocking: {'block': [], 'unblock: []}
        """
        raise NotImplementedError
    
    @abc.abstractmethod
    def block_detection(self, detection: VectraDetection) -> list:
        """
        Block a VectraDetection instance on the corresponding FW/NAC
        :rtype: list of all elements that were blocked
        """
        raise NotImplementedError

    @abc.abstractmethod
    def unblock_detection(self, detection: VectraDetection) -> list:
        """
        Unblock a VectraDetection instance on the corresponding FW/NAC
        :rtype: list of all elements that were unblocked
        """
        raise NotImplementedError
    