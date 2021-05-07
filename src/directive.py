import yaml
import commands
from utils import cidr_to_subnet

with open('nstar_directive.yaml') as yaml_file:
    directive = yaml.load(yaml_file, Loader=yaml.FullLoader)


class NstarDirective(object):
    def __init__(self):
        self.devices = self.get_devices()

    def get_devices(self):
        return [device for device, data in directive.items()]

    def get_interfaces(self, device):
        return [_int for _int, data in directive[device].items()]
    
    def get_interface_status(self, device, interface):
        return directive[device][interface]['state']

    def get_interface_prefix(self, device, interface):
        return directive[device][interface]['prefix']

'''
class Interface(object):
    def __init__(self, data):
        self.data = data

        self.interface = 

class NstarDirective(object):
    def __init__(self,
        target,
        interface=None,
        acl=None,
        acl=None
    ):
        self.target= target
        if self.interface:
            self.interface_


    def devices(self):
        
    def interfaces(self):
        try:
            for 

class Interface(object):
    def __init__(self, device,device_details):
        self.device = deviice
        self.


class DeviceDetails(object):


class AcessList(object):
    def __init__(self, device_details):

class Devices(object):
    def __init__(self, device_details)

target = target
target_connection = ConnectHandler(
    device_type= 'cisco_ios',
    host= target,
    username= 'nstar',
    password= 'nstar'
)
interface_name = 'g2/0'
interface_details = directive[target]['interfaces'][interface_name]

def set_interface_state(self):
    expected_state = interface_details['state']
    execute_command = commands.interface[expected_state]
    execute_command = [f"""int {interface_name}""", commands.interface[expected_state]]
    target_connection.send_config_set(commands.rest_position)
    return target_connection.send_config_set(execute_command)
'''