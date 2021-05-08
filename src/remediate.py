import yaml
import commands
from utils import cidr_to_subnet
from netmiko import ConnectHandler
from directive import SecurityPolicies
import logging
from decouple import config

username = config('_USERNAME') # nstar
password = config('_PASSWORD') # nstar

class RemediateDevice(object):
    """
        Class:
            - Used to establish an connection of SSH to the passed device.
            - Contains functionality to get and set configs on the device.
    """
    def __init__(
        self,
        target,
    ):
        self.target = target
        self.policies = SecurityPolicies()
        self.target_connection = ConnectHandler(
            device_type= 'cisco_ios',
            host= self.target,
            username= username,
            password= password
        )

    # Used to set the interface state on the device to whats specified in the security policy
    def set_interface_state(self, interface_name):
        expected_state = self.policies.get_interface_directed_state(interface_name)
        execute_command = commands.interface[expected_state]
        execute_command = [
            f'int {interface_name}',
            commands.interface[expected_state]
        ]
        logging.info(
            f"Setting interface state \
                Running {execute_command} on {self.target}"
        )
        self.target_connection.config_mode()
        return self.target_connection.send_config_set(execute_command)

    # Used to set access-lists on the device to whats specified in the security policy
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
                f"access-list {acl_index} {state} {protocol} \
                    {_from} {from_wild_card} \
                    {_to} {to_wild_card} eq {port}"
            )
        logging.info(
            f"Setting access-list info \
                Running {execute_command} on {self.target}"
        )
        return self.target_connection.send_config_set(execute_command)

    # Used to get the access-list info from the security policy
    def get_acl_details(self, target, acl_state):
        logging.info(
            f"Getting access-list info from directive for {self.target}"
        )
        return self.policies.directive_details[self.target]['acls'][acl_state]

    # Used to get the interface details from the security policy
    def get_interface_details(self, target, interface_name):
        logging.info(
            f"Getting interface info from directive for {self.target}"
        )
        return self.policies.directive_details[self.target]['interfaces'][interface_name]

    # Used to get the current configured access-list info from the device
    def get_current_acl_details(self):
        logging.info(
            f"Getting access-list info device for {self.target}"
        )
        self.target_connection.exit_config_mode()
        return self.target_connection.send_config_set(commands.show_acl_list)