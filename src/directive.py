import yaml
import commands
from utils import cidr_to_subnet
from decouple import config
_yaml = config('_FILE_PATH')
with open(_yaml) as yaml_file:
    directive = yaml.load(yaml_file, Loader=yaml.FullLoader)

class SecuritPolicies(object):
    """
        Class:
            - Used as a means of retrieving the security policies
              which should be configured on the devices
    """

    def __init__(self):
        self.devices = self.get_devices()
        self.directive_details = directive

    # Used to get the devices stated in the security policy
    def get_devices(self):
        return [device for device, data in directive.items()]

    # Used to get the security policies for each interface on a specific device
    def get_interfaces(self, device):
        return [_int for _int, data in directive[device].items()]
    
    # Used to get the expected state of a device port from the security policy
    def get_interface_status(self, device, interface):
        return directive[device][interface]['state']

    # Used to get the expected prefix of a device port from the security policy
    def get_interface_prefix(self, device, interface):
        return directive[device][interface]['prefix']