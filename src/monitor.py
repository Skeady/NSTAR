from pysnmp.hlapi import *
from directive import NstarDirective
from remediate import *
import commands
import time


MonitorDevice(object):
    def __init__(self, device):
        self.device = device

    def get_interface_current_state(self):
        current_state = {self.device: {}}
        for _, _, _, varBinds in nextCmd(
                SnmpEngine(),
                CommunityData(
                    'NSTAR',
                    mpModel=1
                ),
                UdpTransportTarget((self.device, 161)),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.2')),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.2.2.1.8')),
                ObjectType(ObjectIdentity('1.3.6.1.4.1.9.2.1.3')),
                lexicographicMode=False):
            descr, status, hostname = varBinds  # unpack the list of resolved objectTypes status 1 = up status 2 = down
            iface_name = descr[1].prettyPrint()  # access the objectSyntax and get its human-readable form
            if iface_name != 'Null0':
                iface_status = status[1].prettyPrint()
                current_state[self.device].update({
                    iface_name:{
                        'state': 'up' if int(iface_status) == 1 else 'down',
                    }
                })
        return current_state

    def check_interface(self):
        current_state = self.get_interface_current_state(self.device)
        for iface_name, iface_data in current_state[device].items():
            if iface_data['state']!= directive[device]['interfaces'][iface_name]['state']:
                remediate_vulnerability = Interface(device, iface_name)
                remediate_vulnerability.set_interface_state()
            else:
                pass
        return

    def check_acl(self, acl_state):
        acl_command_output = RemediateDevice(self.device).get_current_acl_details()
        re_acl_pattern = re.compile("    \d+ (deny|permit) [a-z]{3} host \d+.\d+.\d+.\d+ host \d+.\d+.\d+.\d+")
        re_acl_index_pattern = re.compile("access list \d+")
        split_command_output = acl_command_output.split('\n')
        acl_current_info = [acl for acl in split_command_output if re_acl_pattern.match(acl)]
        acl_index = re_acl_index_pattern.find(acl_command_output).split('access list ')[1]
        acl_index = f"""index-{acl_index}"""
        acl_desired_info = directive[self.device]['acls'][acl_state][acl_index]
        re_desired_acl = re.compile(f"""\d+ {commands.access_list[acl_state]} {acl_desired_info['from']} host\
                                    {acl_desired_info['to']} eq ({('|').join(acl_desired_info['ports'])})""")
        failed_entrys = []
        for entry in acl_current_info:
            if not re_desired_acl.match(entry):
                failed_entrys.append(entry)
        if failed_entrys:
            remediate_vulnerability = AccessList(self.device, acl_state)
            remediate_vulnerability.set_access_list()

        

# print(iface_status, iface_name)
	print("HostName {_hostname} Interface {iface} status is {status}".format(_hostname=host_name,iface=iface_name,status=iface_status))

current_state = {'device':{''}}

def check_interface(device):
    current_state = get_interface_current_state(device)
    for iface_name, iface_data in current_state[device].items():
        if iface_data['state']!= directive[device]['interfaces'][iface_name]['state']:
            remediate_vulnerability = Interface(device, iface_name)
            remediate_vulnerability.set_interface_state()
        else:
            pass
    return




def monitor_devices():
    expected = NSTARDirective()
    host_list = list(directive.keys())
    while True:
        for host in host_list:
            device = MonitorDevice(host)
            device.check_interface()
            device.check_acl('blocked')
        time.sleep(5)

'''
iterator = nextCmd(
    SnmpEngine(),
    CommunityData('nsar-ro', mpModel=1),
    UdpTransportTarget(('1.1.1.1', 161)),
    ContextData(),
    ObjectType(ObjectIdentity('IF-MIB', 'ifOperStatus', 1)),
    ObjectType(ObjectIdentity('IF-MIB', 'ifDescr', 1))
)

ObjectType(ObjectIdentity('1.3.6.1.4.1.9.9.808')),

iterator = nextCmd(
    SnmpEngine(),
    CommunityData('NSTAR', mpModel=1),
    UdpTransportTarget(('1.1.1.1', 161)),
    ContextData(),
    ObjectType(ObjectIdentity('1.3.6.1.4.1.9.9.808.1.1.2')),
)
eind, estat, eindex, vbinds = next(iterator)

if eind:
    print('eind', eind)
elif estat:
    print('estat', estat)
else:
    for bind in vbinds:
        print('in vbind')
        print('bind = ', bind)
        print(' = '.join([x.prettyPrint() for x in bind]))

for _, _, _, varBinds in nextCmd(
		SnmpEngine(),
		CommunityData(
			'NSTAR',
			mpModel=1
		),
		UdpTransportTarget(('1.1.1.1', 161)),
		ContextData(),
		ObjectType(ObjectIdentity('1.3.6.1.4.1.9.9.808')),
		lexicographicMode=False):
        print(varBinds)
	descr, status, hostname = varBinds  # unpack the list of resolved objectTypes
	iface_name = descr[1].prettyPrint()  # access the objectSyntax and get its human-readable form
	iface_status = status[1].prettyPrint()
	host_name = hostname[1].prettyPrint()
# print(iface_status, iface_name)
	print("HostName {_hostname} Interface {iface} status is {status}".format(_hostname=host_name,iface=iface_name,status=iface_status))

iterator = nextCmd(
    SnmpEngine(),
    CommunityData('nsar-ro', mpModel=1),
    UdpTransportTarget(('1.1.1.1', 161)),
    ContextData(),
    ObjectType(ObjectIdentity('IF-MIB', 'ifOperStatus', 1)),
    ObjectType(ObjectIdentity('IF-MIB', 'ifDescr', 1))
)
'''