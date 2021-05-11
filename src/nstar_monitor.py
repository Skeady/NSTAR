from pysnmp.hlapi import *
from directive import SecuritPolicies
from remediate import *
import commands
import time
import re

class MonitorDevice(object):
    """
        Class: 
            - Gets device current network network confiugrations 
            - Compares them to the security policies in the SecurityPolicies()
            - Executes remediation if the devices current configs are none compliant with the security policy
    """
    def __init__(self, device):
        self.device = RemediateDevice(device)
        self.directive = SecuritPolicies().directive_details
    
    # Uses SNMP to get device interface status
    def get_interface_current_state(self):
        current_state = {self.device.target: {}}
        for _, _, _, varBinds in nextCmd(
                SnmpEngine(),
                CommunityData(
                    'NSTAR',
                    mpModel=1
                ),
                UdpTransportTarget((self.device.target, 161)),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.2')),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.8')),
                ObjectType(ObjectIdentity('1.3.6.1.4.1.9.2.1.3')),
                lexicographicMode=False):
            descr, status, hostname = varBinds
            iface_name = descr[1].prettyPrint()
            if iface_name != 'Null0':
                iface_status = status[1].prettyPrint()
                current_state[self.device.target].update({
                    iface_name:{
                        'state': 'up' if int(iface_status) == 1 else 'down',
                    }
                })
        return current_state

    # Compares the device interface security policy to whats cofigured on the device
    # Executes remediation if the device is none compliant
    def check_interface(self):
        current_state = self.get_interface_current_state()
        logging.info(
            f"Current Interface State: \
            \n{current_state}"
        )
        for iface_name, iface_data in current_state[self.device.target].items():
            if iface_data['state']!= self.directive[self.device.target]['interfaces'][iface_name]['state']:
                logging.warning(
                    f"{self.device.target} interface {iface_name} is not as expected executing remediation"
                )
                remediate_vulnerability = ' - '.join(
                    self.device.set_interface_state(iface_name).split('\n')
                )
                logging.info(
                    f"Remediation Response: \
                    \n{remediate_vulnerability}"
                )
            else:
                pass
        return

    # Compares the device ACL security policy to whats cofigured on the device
    # Executes remediation if the device is none compliant
    def check_acl(self, acl_state):
        acl_command_output = self.device.get_current_acl_details()
        re_acl_pattern = re.compile("    \d+ (deny|permit) [a-z]{3} host \d+.\d+.\d+.\d+ host \d+.\d+.\d+.\d+")
        if not re_acl_pattern .match(acl_command_output):
            logging.warning(
                f"No access-list information found for {self.device.target} executing remediation"
            )
            remediate_vulnerability = ' - '.join(
                self.device.set_acl_details(acl_state).split('\n')
            )
            logging.info(
                f"Remediation Response: \
                \n{remediate_vulnerability}"
            )
            self.device.target_connection.disconnect()
            return
        re_acl_index_pattern = re.compile("access list \d+")
        split_command_output = acl_command_output.split('\n')
        acl_current_info = [acl for acl in split_command_output if re_acl_pattern.match(acl)]
        acl_index = re_acl_index_pattern.findall(acl_command_output)[0].split('access list ')[1]
        acl_index = f"index-{acl_index}"
        acl_desired_info = self.directive[self.device.target]['acls'][acl_state][acl_index]
        re_desired_acl = re.compile(
            f"\d+ {commands.access_list[acl_state]} {acl_desired_info['from']} host\
            {acl_desired_info['to']} eq ({('|').join(acl_desired_info['ports'])})"
        )
        failed_entrys = []
        if not acl_current_info:
            logging.warning(
                f"access-list information on {self.device.target} is not as expected executing remediation"
            )
            remediate_vulnerability = ' - '.join(
                self.device.set_acl_details(acl_state).split('\n')
            )
            logging.info(
                f"Remediation Response: \
                \n{remediate_vulnerability}"
            )
            self.device.target_connection.disconnect()
        else:
            for entry in acl_current_info:
                if not re_desired_acl.match(entry):
                    failed_entrys.append(entry)
            if failed_entrys:
                logging.warning(
                    f"The following access-list information on {self.device.target} does not match: \
                    \n{failed_entrys}"
                )
                remediate_vulnerability = ' - '.join(
                    self.device.set_acl_details(acl_state).split('\n')
                )
                logging.info(
                    f"Remediation Response:\
                    \n{remediate_vulnerability}"
                )
        return

# Used to execute MonitorDevice class for each host
def monitor_devices():
    directive = SecuritPolicies().directive_details
    host_list = list(directive.keys())
    for host in host_list:
        logging.info(
            f"Running Audit on {host}"
        )
        device = MonitorDevice(host)
        device.check_interface()
        for acl_state in ['blocked']:
            device.check_acl(acl_state)
    return