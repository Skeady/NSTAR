import yaml
import commands
from utils import cidr_to_subnet
from netmiko import ConnectHandler
#from decouple import config

# SSH Command - ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -l nstar 1.1.1.1 -c aes128-cbc
#username = config('USERNAME') # nstar
#password = config('PASSWORD') # nstar
with open('nstar_directive.yaml') as yaml_file:
    directive = yaml.load(yaml_file, Loader=yaml.FullLoader)

class RemediateDevice(object):
    def __init__(
        self,
        target,
    ):
        self.target = target
        self.target_connection = ConnectHandler(
            device_type= 'cisco_ios',
            host= self.target,
            username= 'nstar',
            password= 'nstar'
    )

    def set_interface_state(self, interface_name):
        expected_state = self.get_interface_details(self.target, interface_name)['state']
        execute_command = commands.interface[expected_state]
        execute_command = [
            'int',
            interface_name,
            commands.interface[expected_state]
        ]
        self.target_connection.config_mode()
        return self.target_connection.send_config_set(execute_command)

    def set_acl_details(self, acl_state):
        acl_details = self.get_acl_details(self.target, acl_state)
        acl_index = list(acl_details.keys())[0]
        state = commands.access_list[acl_state]
        protocol = acl_details[acl_index]['protocol']
        _from = acl_details[acl_index]['from']
        from_wild_card = acl_details[acl_index]['from_wild_card']
        _to = acl_details[acl_index]['to']
        to_wild_card = acl_details[acl_index]['to_wild_card']
        ports = acl_details[acl_index]['ports']
        acl_index = acl_index.split('-')[1]
        self.target_connection.config_mode()
        execute_command = []
        for port in ports:
            execute_command.append(
                f"""access-list {acl_index} {state} {protocol} \
                    {_from} {from_wild_card} \
                    {_to} {to_wild_card} eq {port}"""
            )
        return self.target_connection.send_config_set(execute_command)

    def get_acl_details(self, target, acl_state):
        return directive[self.target]['acls'][acl_state]

    def get_interface_details(self, target, interface_name):
        return directive[self.target]['interfaces'][interface_name]

    def get_current_acl_details(self):
        self.target_connection.exit_config_mode()
        return self.target_connection.send_config_set(commands.show_acl_list)


"""
class Interface(object):
    def __init__(self, target, interface_name):
        self.target = target
        self.target_connection = Device(self.target).target_connection
        self.interface_name = interface_name
        self.interface_details = directive[self.target]['interfaces'][self.interface_name]
        self.disconnect = self.target_connection.disconnect()
    
    def set_interface_state(self):
        expected_state = self.interface_details['state']
        execute_command = commands.interface[expected_state]
        execute_command = [
            'int',
            self.interface_name,
            commands.interface[expected_state]
        ]
        self.target_connection.send_config_set(commands.rest_position)
        return self.target_connection.send_config_set(execute_command)
    
    def set_interface_acl(self, index, direction):
        execute_command = [
            'int',
            self.interface_name,
            commands.interface['acl_group'].format(
                index=index,
                direction=direction
            )
        ]
        self.target_connection.send_config_set(commands.rest_position)
        return self.target_connection.send_config_set(execute_command)

class Test(object):
    def __init__(self, target, acl_state):
        self.target = target
        self.target_connection = Device(self.target).target_connection
        self.acl_state = acl_state
        self.acl_details = directive[self.target]['acls'][self.acl_state]
        self.disconnect = self.target_connection.disconnect()
        
    def set_access_list(self):
        acl_index = list(self.acl_details.keys())[0]
        state = commands.access_list[self.acl_state]
        protocol = self.acl_details[acl_index]['protocol']
        _from = self.acl_details[acl_index]['from']
        from_wild_card = self.acl_details[acl_index]['from_wild_card']
        _to = self.acl_details[acl_index]['to']
        to_wild_card = self.acl_details[acl_index]['to_wild_card']
        ports = self.acl_details[acl_index]['ports']
        acl_index = acl_index.split('-')[1]
        self.target_connection.send_config_set(commands.rest_position)
        execute_command = []
        for port in ports:
            execute_command.append(
                f "access-list {acl_index} {state} {protocol} \
                    {_from} {from_wild_card} \
                    {_to} {to_wild_card} eq {port}"
            )
        return self.target_connection.send_config_set(execute_command)

    def apply_acl_to_interface(self):


    def set_interface_prefix(self):

    def set_interface_state(self, interface_name, target):
        expected_state = directive[self.target]['interfaces'][interface_name]['state']
        execute_command = commands.interface[expected_state]
        result = self.target_connection.send_config_set(commands['set_state'])
        return result
        
    def state(self, interface_name, target):
        expected_state = directive[self.target]['interfaces'][interface_name]['state']
        execute_command = [interface_name, commands.interface[expected_state]]
        self.target_connection.send_config_set(commands.rest_position)
        return self.target_connection.send_config_set(commands['set_state'])

    def set_acl(self, state, target):

Class AcessList(object):
    def __init__(
        self,
        target,
        state
    ):
        self.target = target
        self.state = state
        self.target_connection = Device(self.target)
    
    def get_acl_info()
    

class Interface(object):
    def __init__(
        self,
        target_connection,
        interface_name
    ):
    self.target = target
    self.target_connection = target_connection
    def state(self, interface_name, target):
        expected_state = directive[self.target]['interfaces'][interface_name]['state']
        execute_command = [interface_name, commands.interface[expected_state]]
        self.target_connection.send_config_set(commands.rest_position)
        return self.target_connection.send_config_set(commands['set_state'])

    def ip_address(self, interface_name, target):
        expected_address = directive[self.target]['interfaces'][interface_name]['ip_address']
        expected_ip, expected_subnet = cidr_to_subnet(expected_address)
        execute_command = [
                'int {}'.format(interface_name),
                commands.interface['ip'].format(ip_address=expected_ip,
                                                subnet_mask=expected_subnet)
        ]
        self.target_connection.send_config_set(commands.rest_position)
        return self.target_connection.send_config_set(execute_command)


    def access_list():

    def version():

    def white_list():

    def black_list():
"""