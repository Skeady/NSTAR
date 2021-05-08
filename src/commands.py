"""
    Commands:
        - General commands to run on the devices
"""
show_acl_list = ['end', 'show access-lists']
interface = {
    'up': 'no shut',
    'down': 'shut',
    'ip': 'ip add {ip_address} {subnet_mask}',
    'description': 'desc {interface_description}',
    'acl_group': 'ip access-group {index} {direction}'
}

access_list = {
    'blocked': 'deny',
    'allow': 'permit',
}