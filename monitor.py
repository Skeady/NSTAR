from pysnmp.hlapi import *
from directive import NstarDirective
from remediate import *
import commands



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

    def check_acl(self):
        device_connection = 

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
    devices = list(directive.keys())
    while True:
        for device in devices:
            check_interface(device)
            check_acl(device)
            current_state = get_interface_current_state(device)
            for iface_name, iface_data in current_state[device].items():
                if iface_data['state']!= directive[device]['interfaces'][iface_name]['state']:
                    remediate_vulnerability = Interface(device, iface_name)
                    remediate_vulnerability.set_interface_state()
            
            expected_state = expected.interfaces(device)

            get_desired_interface_states(device)

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