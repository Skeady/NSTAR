import re
import yaml
from decouple import config

report = open(
    config('_INTELLIGANCE_REPORT'), "r"
).read()

policies = config('_FILE_PATH')

def scrape_security_policies():
    re_prefix = re.compile('\d+.\d+.\d+.\d+')
    re_port = re.compile('port \d+')
    re_state = re.compile('(blocked|allowed)')
    re_protocol = re.compile('(tcp|udp)')
    re_acl_pattern = re.compile('(\d+.\d+.\d+.\d+(...)+\d+)')
    acl_info = re_acl_pattern.findall(report)
    scrapped_policies = {}
    for acl in acl_info:
        ports = re_port.findall(acl[0])
        ports = ''.join(ports).split('port ')
        ports.pop(0)
        scrapped_policies.update(
            {
                'index-150':{
                    re_state.findall(acl[0])[0]: {
                        'from': re_prefix.findall(acl[0])[0],
                        'from_wild_card': '0.0.0.0',
                        'to': '209.165.200.225',
                        'to_wild_card': '0.0.0.0',
                        'protocol': re_protocol.findall(acl[0])[0],
                        'ports': ports
                    }
                }
            }
        )
        
    return scrapped_policies

def update_security_policies(scrapped_policies):
    with open(policies) as yaml_file:
        security_policies = yaml.load(yaml_file)
    security_policies['1.1.1.1']['acls'] = scrapped_policies
    with open(policies, 'w') as f: 
        yaml.dump(security_policies,f)
    return

