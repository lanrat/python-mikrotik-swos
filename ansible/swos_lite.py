#!/usr/bin/python
# -*- coding: utf-8 -*-


from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: swos_lite
short_description: Manage MikroTik SwOS Lite switch configuration
version_added: "1.0.0"
description:
    - Manages configuration of MikroTik switches running SwOS Lite 2.20+
    - Supports configuring ports, PoE, LAG/LACP, VLANs, and SNMP
    - Implements idempotent operations (only applies changes when needed)
    - Supports check mode for dry-run validation
    - Only modifies writable settings (read-only settings like link status are ignored)
options:
    host:
        description:
            - IP address or hostname of the switch
            - Can be provided with or without http:// prefix
        required: true
        type: str
    username:
        description:
            - Username for authentication
            - Uses HTTP Digest Authentication
        required: false
        default: admin
        type: str
    password:
        description:
            - Password for authentication
            - Use Ansible Vault for secure password storage
        required: false
        default: ""
        type: str
    config:
        description:
            - Complete switch configuration dictionary organized by sections
            - Supported sections are ports, poe, lag, port_vlans, snmp
            - Each section contains a list of per-port configurations (except snmp)
            - Only specified ports in each section will be evaluated for changes
            - The system section is ignored (read-only, for documentation only)
        required: false
        type: dict
        suboptions:
            ports:
                description:
                    - List of port configuration dictionaries
                type: list
                elements: dict
                suboptions:
                    port:
                        description: Port number (1-based)
                        required: true
                        type: int
                    name:
                        description: Port name
                        type: str
                    enabled:
                        description: Port enabled state
                        type: bool
                    auto_negotiation:
                        description: Auto-negotiation enabled
                        type: bool
            poe:
                description:
                    - List of PoE configuration dictionaries
                type: list
                elements: dict
                suboptions:
                    port:
                        description: Port number (1-based)
                        required: true
                        type: int
                    mode:
                        description: PoE mode
                        type: str
                        choices: ['off', 'on', 'auto']
                    priority:
                        description: PoE priority (1-8, where 1 is highest)
                        type: int
                    voltage_level:
                        description: Voltage level setting
                        type: str
                        choices: ['auto', 'low', 'high']
                    lldp_enabled:
                        description: LLDP enabled state
                        type: bool
            lag:
                description:
                    - List of LAG/LACP configuration dictionaries
                type: list
                elements: dict
                suboptions:
                    port:
                        description: Port number (1-based)
                        required: true
                        type: int
                    mode:
                        description: LACP mode
                        type: str
                        choices: ['passive', 'active', 'static']
                    group:
                        description: LAG group number
                        type: int
            port_vlans:
                description:
                    - List of per-port VLAN configuration dictionaries
                type: list
                elements: dict
                suboptions:
                    port:
                        description: Port number (1-based)
                        required: true
                        type: int
                    vlan_mode:
                        description: VLAN mode
                        type: str
                        choices: ['Disabled', 'Optional', 'Enabled', 'Strict']
                    vlan_receive:
                        description: VLAN receive filter
                        type: str
                        choices: ['Any', 'Only Tagged', 'Only Untagged']
                    default_vlan_id:
                        description: Default VLAN ID for untagged traffic
                        type: int
            snmp:
                description:
                    - SNMP configuration dictionary
                type: dict
                suboptions:
                    enabled:
                        description: SNMP enabled state
                        type: bool
                    community:
                        description: SNMP community string
                        type: str
                    contact:
                        description: Contact information
                        type: str
                    location:
                        description: Device location
                        type: str
    port_vlans:
        description:
            - List of port VLAN configurations (deprecated, use config.port_vlans)
        required: false
        type: list
        elements: dict
notes:
    - Requires swos_lite_api.py to be in the parent directory
    - Only applies changes when configuration differs from current state
    - All write operations send complete configuration to the switch
    - Read-only settings are automatically ignored
    - Use check mode (--check) to preview changes without applying them
requirements:
    - requests>=2.25.0
author:
    - SwOS Lite Ansible Module Contributors
'''

EXAMPLES = r'''
# Apply complete configuration from YAML file
- name: Apply switch configuration
  swos_lite:
    host: 192.168.1.7
    username: admin
    password: ""
    config: "{{ lookup('file', 'switch_config.yml') | from_yaml }}"
  register: result

# Configure port settings only
- name: Configure port names and states
  swos_lite:
    host: 192.168.1.7
    config:
      ports:
        - port: 1
          name: "Uplink"
          enabled: true
          auto_negotiation: true
        - port: 2
          name: "Server1"
          enabled: true

# Configure PoE settings
- name: Configure PoE on multiple ports
  swos_lite:
    host: 192.168.1.7
    config:
      poe:
        - port: 1
          mode: "auto"
          priority: 1
          voltage_level: "auto"
          lldp_enabled: true
        - port: 2
          mode: "off"

# Configure LAG/LACP
- name: Configure LACP trunk
  swos_lite:
    host: 192.168.1.7
    config:
      lag:
        - port: 9
          mode: "active"
          group: 1
        - port: 10
          mode: "active"
          group: 1

# Configure VLANs
- name: Configure port VLANs
  swos_lite:
    host: 192.168.1.7
    config:
      port_vlans:
        - port: 3
          vlan_mode: "Enabled"
          vlan_receive: "Only Untagged"
          default_vlan_id: 64
        - port: 4
          vlan_mode: "Optional"
          vlan_receive: "Any"
          default_vlan_id: 1

# Configure SNMP
- name: Configure SNMP settings
  swos_lite:
    host: 192.168.1.7
    config:
      snmp:
        enabled: true
        community: "public"
        contact: "admin@example.com"
        location: "Server Room A"

# Configure multiple sections at once
- name: Configure ports, PoE, and VLANs
  swos_lite:
    host: 192.168.1.7
    username: admin
    password: ""
    config:
      ports:
        - port: 1
          name: "Uplink"
          enabled: true
      poe:
        - port: 2
          mode: "auto"
          priority: 1
      port_vlans:
        - port: 3
          vlan_mode: "Enabled"
          default_vlan_id: 100

# Use with Ansible Vault for password
- name: Apply configuration with vault password
  swos_lite:
    host: 192.168.1.7
    username: admin
    password: "{{ vault_switch_password }}"
    config: "{{ switch_config }}"

# Check mode - preview changes without applying
- name: Preview configuration changes
  swos_lite:
    host: 192.168.1.7
    config: "{{ switch_config }}"
  check_mode: yes
'''

RETURN = r'''
changed:
    description: Whether any changes were made to the switch configuration
    type: bool
    returned: always
    sample: true
msg:
    description: Human-readable message describing what was changed
    type: str
    returned: always
    sample: "Changed 3 setting(s): Port 1 config (name 'Port1'->'Uplink'); Port 2 PoE (mode auto->off); Port 3 VLAN (mode Optional->Enabled)"
current_config:
    description: Current configuration after changes (only if changes were made)
    type: dict
    returned: success
    contains:
        ports:
            description: Current port configuration (if ports section was provided)
            type: list
            returned: when ports were configured
        poe:
            description: Current PoE configuration (if poe section was provided)
            type: list
            returned: when PoE was configured
        lag:
            description: Current LAG configuration (if lag section was provided)
            type: list
            returned: when LAG was configured
        port_vlans:
            description: Current per-port VLAN configuration (if port_vlans section was provided)
            type: list
            returned: when VLANs were configured
    sample:
        port_vlans:
            - port_number: 1
              vlan_mode: "Optional"
              vlan_receive: "Any"
              default_vlan_id: 1
'''

from ansible.module_utils.basic import AnsibleModule
import sys
import os

# Add parent directory to path to import swos_lite_api
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from swos_lite_api import (
        get_port_vlans, set_port_vlan,
        get_links, set_port_config,
        get_poe, set_poe_config,
        get_lag, set_lag_config,
        get_snmp, set_snmp
    )
    HAS_SWOS_LITE_API = True
except ImportError:
    HAS_SWOS_LITE_API = False


def port_vlan_matches(current, desired):
    """Check if current port VLAN config matches desired config"""
    matches = True

    if 'vlan_mode' in desired and current.get('vlan_mode') != desired['vlan_mode']:
        matches = False

    if 'vlan_receive' in desired and current.get('vlan_receive') != desired['vlan_receive']:
        matches = False

    if 'default_vlan_id' in desired and current.get('default_vlan_id') != desired['default_vlan_id']:
        matches = False

    return matches


def port_config_matches(current, desired):
    """Check if current port config matches desired config"""
    matches = True

    if 'name' in desired and current.get('port_name') != desired['name']:
        matches = False

    if 'enabled' in desired and current.get('enabled') != desired['enabled']:
        matches = False

    if 'auto_negotiation' in desired and current.get('auto_negotiation') != desired['auto_negotiation']:
        matches = False

    return matches


def poe_config_matches(current, desired):
    """Check if current PoE config matches desired config"""
    matches = True

    if 'mode' in desired and current.get('poe_mode') != desired['mode']:
        matches = False

    if 'priority' in desired and current.get('poe_priority') != desired['priority']:
        matches = False

    if 'voltage_level' in desired and current.get('voltage_level') != desired['voltage_level']:
        matches = False

    if 'lldp_enabled' in desired and current.get('lldp_enabled') != desired['lldp_enabled']:
        matches = False

    return matches


def lag_config_matches(current, desired):
    """Check if current LAG config matches desired config"""
    matches = True

    if 'mode' in desired and current.get('lacp_mode') != desired['mode']:
        matches = False

    if 'group' in desired and current.get('lacp_group') != desired['group']:
        matches = False

    return matches


def snmp_config_matches(current, desired):
    """Check if current SNMP config matches desired config"""
    matches = True

    if 'enabled' in desired and current.get('enabled') != desired['enabled']:
        matches = False

    if 'community' in desired and current.get('community') != desired['community']:
        matches = False

    if 'contact' in desired and current.get('contact') != desired['contact']:
        matches = False

    if 'location' in desired and current.get('location') != desired['location']:
        matches = False

    return matches


def run_module():
    module_args = dict(
        host=dict(type='str', required=True),
        username=dict(type='str', required=False, default='admin'),
        password=dict(type='str', required=False, default='', no_log=True),
        config=dict(type='dict', required=False, default={}),
        port_vlans=dict(type='list', elements='dict', required=False, default=[]),
    )

    result = dict(
        changed=False,
        msg='',
        current_config={}
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if not HAS_SWOS_LITE_API:
        module.fail_json(msg='swos_lite_api module is required. Ensure swos_lite_api.py is in the parent directory.')

    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    config = module.params['config']
    port_vlans = module.params['port_vlans']

    # Support both new config format and old port_vlans parameter
    if config and 'port_vlans' in config:
        port_vlans = config['port_vlans']

    # Build URL
    if not host.startswith('http'):
        url = f"http://{host}"
    else:
        url = host

    try:
        # Track all changes across all sections
        all_changes = []

        # Process ports configuration
        if config and 'ports' in config:
            current_ports = get_links(url, username, password)
            for port_cfg in config['ports']:
                port_num = port_cfg['port']

                if port_num < 1 or port_num > len(current_ports):
                    module.fail_json(msg=f"Invalid port number: {port_num}")

                current = current_ports[port_num - 1]

                if not port_config_matches(current, port_cfg):
                    change_desc = []
                    if 'name' in port_cfg and current.get('port_name') != port_cfg['name']:
                        change_desc.append(f"name '{current.get('port_name')}'->'{port_cfg['name']}'")
                    if 'enabled' in port_cfg and current.get('enabled') != port_cfg['enabled']:
                        change_desc.append(f"enabled {current.get('enabled')}->{port_cfg['enabled']}")
                    if 'auto_negotiation' in port_cfg and current.get('auto_negotiation') != port_cfg['auto_negotiation']:
                        change_desc.append(f"auto-neg {current.get('auto_negotiation')}->{port_cfg['auto_negotiation']}")

                    all_changes.append(f"Port {port_num} config ({', '.join(change_desc)})")

                    if not module.check_mode:
                        set_port_config(
                            url, username, password, port_num,
                            name=port_cfg.get('name'),
                            enabled=port_cfg.get('enabled'),
                            auto_negotiation=port_cfg.get('auto_negotiation')
                        )

        # Process PoE configuration
        if config and 'poe' in config:
            current_poe = get_poe(url, username, password)
            for poe_cfg in config['poe']:
                port_num = poe_cfg['port']

                if port_num < 1 or port_num > len(current_poe):
                    module.fail_json(msg=f"Invalid port number: {port_num}")

                current = current_poe[port_num - 1]

                if not poe_config_matches(current, poe_cfg):
                    change_desc = []
                    if 'mode' in poe_cfg and current.get('poe_mode') != poe_cfg['mode']:
                        change_desc.append(f"mode {current.get('poe_mode')}->{poe_cfg['mode']}")
                    if 'priority' in poe_cfg and current.get('poe_priority') != poe_cfg['priority']:
                        change_desc.append(f"priority {current.get('poe_priority')}->{poe_cfg['priority']}")
                    if 'voltage_level' in poe_cfg and current.get('voltage_level') != poe_cfg['voltage_level']:
                        change_desc.append(f"voltage {current.get('voltage_level')}->{poe_cfg['voltage_level']}")
                    if 'lldp_enabled' in poe_cfg and current.get('lldp_enabled') != poe_cfg['lldp_enabled']:
                        change_desc.append(f"LLDP {current.get('lldp_enabled')}->{poe_cfg['lldp_enabled']}")

                    all_changes.append(f"Port {port_num} PoE ({', '.join(change_desc)})")

                    if not module.check_mode:
                        set_poe_config(
                            url, username, password, port_num,
                            mode=poe_cfg.get('mode'),
                            priority=poe_cfg.get('priority'),
                            voltage_level=poe_cfg.get('voltage_level'),
                            lldp_enabled=poe_cfg.get('lldp_enabled')
                        )

        # Process LAG configuration
        if config and 'lag' in config:
            current_lag = get_lag(url, username, password)
            for lag_cfg in config['lag']:
                port_num = lag_cfg['port']

                if port_num < 1 or port_num > len(current_lag):
                    module.fail_json(msg=f"Invalid port number: {port_num}")

                current = current_lag[port_num - 1]

                if not lag_config_matches(current, lag_cfg):
                    change_desc = []
                    if 'mode' in lag_cfg and current.get('lacp_mode') != lag_cfg['mode']:
                        change_desc.append(f"mode {current.get('lacp_mode')}->{lag_cfg['mode']}")
                    if 'group' in lag_cfg and current.get('lacp_group') != lag_cfg['group']:
                        change_desc.append(f"group {current.get('lacp_group')}->{lag_cfg['group']}")

                    all_changes.append(f"Port {port_num} LAG ({', '.join(change_desc)})")

                    if not module.check_mode:
                        set_lag_config(
                            url, username, password, port_num,
                            mode=lag_cfg.get('mode'),
                            group=lag_cfg.get('group')
                        )

        # Process port VLAN configuration
        # Support both new config format and old port_vlans parameter
        if config and 'port_vlans' in config:
            port_vlans = config['port_vlans']

        if port_vlans:
            current_vlans = get_port_vlans(url, username, password)
            for port_vlan in port_vlans:
                port_num = port_vlan['port']

                if port_num < 1 or port_num > len(current_vlans):
                    module.fail_json(msg=f"Invalid port number: {port_num}")

                current = current_vlans[port_num - 1]

                if not port_vlan_matches(current, port_vlan):
                    change_desc = []
                    if 'vlan_mode' in port_vlan and current.get('vlan_mode') != port_vlan['vlan_mode']:
                        change_desc.append(f"mode {current.get('vlan_mode')}->{port_vlan['vlan_mode']}")
                    if 'vlan_receive' in port_vlan and current.get('vlan_receive') != port_vlan['vlan_receive']:
                        change_desc.append(f"receive {current.get('vlan_receive')}->{port_vlan['vlan_receive']}")
                    if 'default_vlan_id' in port_vlan and current.get('default_vlan_id') != port_vlan['default_vlan_id']:
                        change_desc.append(f"vlan {current.get('default_vlan_id')}->{port_vlan['default_vlan_id']}")

                    all_changes.append(f"Port {port_num} VLAN ({', '.join(change_desc)})")

                    if not module.check_mode:
                        set_port_vlan(
                            url, username, password, port_num,
                            vlan_mode=port_vlan.get('vlan_mode'),
                            vlan_receive=port_vlan.get('vlan_receive'),
                            default_vlan_id=port_vlan.get('default_vlan_id')
                        )

        # Process SNMP configuration
        if config and 'snmp' in config:
            current_snmp = get_snmp(url, username, password)
            snmp_cfg = config['snmp']

            if current_snmp and not snmp_config_matches(current_snmp, snmp_cfg):
                change_desc = []
                if 'enabled' in snmp_cfg and current_snmp.get('enabled') != snmp_cfg['enabled']:
                    change_desc.append(f"enabled {current_snmp.get('enabled')}->{snmp_cfg['enabled']}")
                if 'community' in snmp_cfg and current_snmp.get('community') != snmp_cfg['community']:
                    change_desc.append(f"community changed")
                if 'contact' in snmp_cfg and current_snmp.get('contact') != snmp_cfg['contact']:
                    change_desc.append(f"contact '{current_snmp.get('contact')}'->'{snmp_cfg['contact']}'")
                if 'location' in snmp_cfg and current_snmp.get('location') != snmp_cfg['location']:
                    change_desc.append(f"location '{current_snmp.get('location')}'->'{snmp_cfg['location']}'")

                all_changes.append(f"SNMP config ({', '.join(change_desc)})")

                if not module.check_mode:
                    set_snmp(
                        url, username, password,
                        enabled=snmp_cfg.get('enabled'),
                        community=snmp_cfg.get('community'),
                        contact=snmp_cfg.get('contact'),
                        location=snmp_cfg.get('location')
                    )

        # Build result message
        if all_changes:
            result['changed'] = True
            result['msg'] = f"Changed {len(all_changes)} setting(s): " + "; ".join(all_changes)
        else:
            result['msg'] = "No changes needed"

        # Get final configuration (only if changes were made)
        if not module.check_mode and result['changed']:
            result['current_config'] = {}
            if config and 'ports' in config:
                result['current_config']['ports'] = get_links(url, username, password)
            if config and 'poe' in config:
                result['current_config']['poe'] = get_poe(url, username, password)
            if config and 'lag' in config:
                result['current_config']['lag'] = get_lag(url, username, password)
            if port_vlans:
                result['current_config']['port_vlans'] = get_port_vlans(url, username, password)
            if config and 'snmp' in config:
                result['current_config']['snmp'] = get_snmp(url, username, password)

        module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg=f"Error: {str(e)}", **result)


def main():
    run_module()


if __name__ == '__main__':
    main()
