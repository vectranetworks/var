import logging
import json
import atexit
import ssl
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim, vmodl
from requests import HTTPError
from enum import Enum, unique, auto
from third_party_clients.third_party_interface import ThirdPartyInterface
from third_party_clients.vmware.vmware_config import VCSA_HOSTS

@unique
class BlockType(Enum):
    """Enumerated type describing the kind of block to be done
    on FortiGate. FortiGate can block source and destination
    addresses.
    """
    CONNECT = auto()
    DISCONNECT = auto()

class VMWareClient(ThirdPartyInterface):
    def __init__(self):
        self.logger = logging.getLogger()
        context = ssl._create_unverified_context()
        self.vcsa_hosts_service_instances = {}
        for vcsa in VCSA_HOSTS:
            # Instantiate a connector for the VCSA
            si = SmartConnect(host=vcsa['HOST'], user=vcsa['USER'], pwd=vcsa['PASS'], sslContext=context)
            if not si:
                raise HTTPError("Cannot connect to specified host using specified username and password")
            atexit.register(Disconnect, si)
            self.vcsa_hosts_service_instances[vcsa['HOST']] = si
        # Instantiate parent class
        ThirdPartyInterface.__init__ (self)

    def block_host(self, host):
        # We use a mix of instance and BIOS UUID
        uuid = host.vmware_vm_uuid[:36]
        # As we don't know the VCSA the host is on, we need to loop
        vm_pointer = None
        for vcsa_host, si in self.vcsa_hosts_service_instances.items():
            content = si.RetrieveContent()
            objView = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
            vmList = objView.view
            objView.Destroy()
            for vm in vmList:
                if vm.summary.config.instanceUuid == uuid:
                    vm_pointer = vm
                    break # Get out of the loop since we found the object
            if vm_pointer:
                self.update_virtual_nic_state(si, vm_pointer, 'disconnect')
                break # break the parent loop as well
        return [uuid]

    def groom_host(self, host) -> dict:
        self.logger.warning('VMWare client does not implement host grooming')
        return []

    def unblock_host(self, host):
        # We use a mix of instance and BIOS UUID. We can use the UUID we have on the host container, not the tag as this in constant.
        uuid = host.vmware_vm_uuid[:36]
        # As we don't know the VCSA the host is on, we need to loop
        vm_pointer = None
        for vcsa_host, si in self.vcsa_hosts_service_instances.items():
            content = si.RetrieveContent()
            objView = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
            vmList = objView.view
            objView.Destroy()
            for vm in vmList:
                if vm.summary.config.instanceUuid == uuid:
                    vm_pointer = vm
                    break # Get out of the loop since we found the object
            if vm_pointer:
                self.update_virtual_nic_state(si, vm_pointer, 'connect')
                break # break the parent loop as well
        return [uuid]
    
    def block_detection(self, detection):
        # this client only implements Host-based blocking
        self.logger.warn('VMWare client does not implement detection-based blocking')
        return []

    def unblock_detection(self, detection):
        # this client only implements Host-basd blocking
        return []
    
    def wait_for_tasks(self, service_instance, tasks):
        """Given the service instance si and tasks, it returns after all the
        tasks are complete
        """
        property_collector = service_instance.content.propertyCollector
        task_list = [str(task) for task in tasks]
        # Create filter
        obj_specs = [vmodl.query.PropertyCollector.ObjectSpec(obj=task)
                    for task in tasks]
        property_spec = vmodl.query.PropertyCollector.PropertySpec(type=vim.Task,
                                                                pathSet=[],
                                                                all=True)
        filter_spec = vmodl.query.PropertyCollector.FilterSpec()
        filter_spec.objectSet = obj_specs
        filter_spec.propSet = [property_spec]
        pcfilter = property_collector.CreateFilter(filter_spec, True)
        try:
            version, state = None, None
            # Loop looking for updates till the state moves to a completed state.
            while len(task_list):
                update = property_collector.WaitForUpdates(version)
                for filter_set in update.filterSet:
                    for obj_set in filter_set.objectSet:
                        task = obj_set.obj
                        for change in obj_set.changeSet:
                            if change.name == 'info':
                                state = change.val.state
                            elif change.name == 'info.state':
                                state = change.val
                            else:
                                continue

                            if not str(task) in task_list:
                                continue

                            if state == vim.TaskInfo.State.success:
                                # Remove task from taskList
                                task_list.remove(str(task))
                            elif state == vim.TaskInfo.State.error:
                                raise task.info.error
                # Move to next version
                version = update.version
        finally:
            if pcfilter:
                pcfilter.Destroy()

    def update_virtual_nic_state(self, si, vm_obj, new_nic_state):
        """
        :param si: Service Instance
        :param vm_obj: Virtual Machine Object
        :param new_nic_state: Either Connect, Disconnect or Delete
        :return: True if success
        """
        virtual_nic_devices = []
        for dev in vm_obj.config.hardware.device:
            if isinstance(dev, vim.vm.device.VirtualEthernetCard):
                virtual_nic_devices.append(dev)
        if not virtual_nic_devices:
            raise RuntimeError('No Virtual Adapters found for {}'.format(vm_obj.name))

        for virtual_nic_device in virtual_nic_devices:
            virtual_nic_spec = vim.vm.device.VirtualDeviceSpec()
            virtual_nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
            virtual_nic_spec.device = virtual_nic_device
            virtual_nic_spec.device.key = virtual_nic_device.key
            virtual_nic_spec.device.macAddress = virtual_nic_device.macAddress
            virtual_nic_spec.device.backing = virtual_nic_device.backing
            virtual_nic_spec.device.wakeOnLanEnabled = virtual_nic_device.wakeOnLanEnabled
            connectable = vim.vm.device.VirtualDevice.ConnectInfo()
            if new_nic_state == 'connect':
                connectable.connected = True
                connectable.startConnected = True
            elif new_nic_state == 'disconnect':
                connectable.connected = False
                connectable.startConnected = False
            else:
                connectable = virtual_nic_device.connectable
            virtual_nic_spec.device.connectable = connectable
            dev_changes = []
            dev_changes.append(virtual_nic_spec)
            spec = vim.vm.ConfigSpec()
            spec.deviceChange = dev_changes
            task = vm_obj.ReconfigVM_Task(spec=spec)
            self.wait_for_tasks(si, [task])
        return True
