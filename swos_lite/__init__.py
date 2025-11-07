#!/usr/bin/env python3
"""
SwOS Lite API Library

Python library for MikroTik SwOS Lite switches (version 2.20+).

Read Operations:
    System info, ports, PoE, LAG/LACP, VLANs, host table, SFP info, SNMP

Write Operations:
    Port config, PoE settings, LAG/LACP, per-port VLANs, SNMP

Example:
    >>> from swos_lite_api import get_system_info, set_port_config
    >>>
    >>> system = get_system_info('http://192.168.1.7', 'admin', '')
    >>> print(f"{system['device_name']} - {system['model']}")
    >>>
    >>> set_port_config('http://192.168.1.7', 'admin', '',
    >>>                 port_number=1, name='Uplink')

Authentication: HTTP Digest (username/password)
Requirements: requests>=2.25.0
Compatibility: SwOS Lite 2.20+ (tested on CSS610-8P-2S+, CSS326-24G-2S+)
"""

import re
import binascii
import requests
from requests.auth import HTTPDigestAuth


def parse_js_object(text):
    """
    Parse JavaScript-like object notation to Python dict/list

    Handles formats like:
    - {i01:0x1234,i02:'hexstring'}
    - [{i01:1,i02:2},{i01:3,i02:4}]
    """
    # Replace JavaScript hex numbers with decimal
    def hex_to_int(match):
        return str(int(match.group(1), 16))

    # Convert 0x notation to integers
    text = re.sub(r'0x([0-9a-fA-F]+)', hex_to_int, text)

    # Replace single quotes with double quotes
    text = text.replace("'", '"')

    # Add quotes around keys (i01, i02, etc.)
    text = re.sub(r'([a-zA-Z_][a-zA-Z0-9_]*):', r'"\1":', text)

    # Now it should be valid JSON
    import json
    return json.loads(text)


def decode_hex_string(hex_str):
    """Decode a hex-encoded ASCII string"""
    try:
        return binascii.unhexlify(hex_str).decode('ascii')
    except:
        return hex_str


def decode_mac_address(hex_str):
    """Decode a hex-encoded MAC address"""
    if len(hex_str) == 12:
        return ':'.join(hex_str[i:i+2] for i in range(0, 12, 2))
    return hex_str


def get_system_info(url, username, password):
    """Fetch and parse system information from sys.b"""
    auth = HTTPDigestAuth(username, password)
    response = requests.get(f"{url}/sys.b", auth=auth)
    response.raise_for_status()

    data = parse_js_object(response.text)

    return {
        'mac_address': decode_mac_address(data.get('i03', '')),
        'serial_number': decode_hex_string(data.get('i04', '')),
        'device_name': decode_hex_string(data.get('i05', '')),
        'version': decode_hex_string(data.get('i06', '')),
        'model': decode_hex_string(data.get('i07', '')),
        'port_mask': data.get('i12', 0),
        'uptime': data.get('i01', 0),
    }


def get_vlans(url, username, password):
    """Fetch and parse VLAN configuration from vlan.b"""
    auth = HTTPDigestAuth(username, password)
    response = requests.get(f"{url}/vlan.b", auth=auth)
    response.raise_for_status()

    data = parse_js_object(response.text)

    vlans = []
    for vlan in data:
        vlans.append({
            'vlan_id': vlan.get('i01', 0),
            'port_mask': vlan.get('i02', 0),
            'settings': vlan.get('i03', 0),
        })

    return vlans


def get_port_vlans(url, username, password):
    """Fetch and parse per-port VLAN configuration from fwd.b"""
    auth = HTTPDigestAuth(username, password)
    response = requests.get(f"{url}/fwd.b", auth=auth)
    response.raise_for_status()

    data = parse_js_object(response.text)

    # VLAN mode mapping
    vlan_modes = {
        0: 'Disabled',
        1: 'Optional',
        2: 'Enabled',
        3: 'Strict',
    }

    # VLAN receive mode mapping
    receive_modes = {
        0: 'Any',
        1: 'Only Tagged',
        2: 'Only Untagged',
    }

    modes = data.get('i15', [])
    receive = data.get('i17', [])
    default_vlans = data.get('i18', [])

    ports = []
    for i in range(len(modes)):
        ports.append({
            'port_number': i + 1,
            'vlan_mode': vlan_modes.get(modes[i], f'Unknown({modes[i]})'),
            'vlan_receive': receive_modes.get(receive[i], f'Unknown({receive[i]})'),
            'default_vlan_id': default_vlans[i],
        })

    return ports


def decode_port_mask(mask, num_ports=10):
    """Convert a port bitmask to a list of port numbers"""
    ports = []
    for i in range(num_ports):
        if mask & (1 << i):
            ports.append(i + 1)
    return ports


def get_hosts(url, username, password):
    """Fetch and parse learned hosts from !dhost.b (dynamic host table)"""
    auth = HTTPDigestAuth(username, password)
    response = requests.get(f"{url}/!dhost.b", auth=auth)
    response.raise_for_status()

    data = parse_js_object(response.text)

    # Parse host table - array of {i01: 'mac_hex', i02: port_index}
    hosts = []
    if isinstance(data, list):
        for host in data:
            mac_hex = host.get('i01', '')
            port_index = host.get('i02', 0)

            # Format MAC address with colons
            mac_address = ':'.join(mac_hex[i:i+2] for i in range(0, len(mac_hex), 2))

            hosts.append({
                'mac_address': mac_address,
                'port_number': port_index + 1,  # Convert 0-based to 1-based
                'port_index': port_index,
            })

    return hosts


def get_links(url, username, password):
    """Fetch and parse port/link information from link.b"""
    auth = HTTPDigestAuth(username, password)
    response = requests.get(f"{url}/link.b", auth=auth)
    response.raise_for_status()

    data = parse_js_object(response.text)

    # Link status mapping
    link_status_map = {
        0x02: 'link on',
        0x07: 'no link',
    }

    port_names = data.get('i0a', [])
    link_status = data.get('i08', [])
    uptime = data.get('i09', [])
    enabled_mask = data.get('i01', 0)
    auto_neg_mask = data.get('i02', 0)
    link_up_mask = data.get('i06', 0)
    full_duplex_mask = data.get('i07', 0)

    ports = []
    for i in range(len(port_names)):
        ports.append({
            'port_number': i + 1,
            'port_name': decode_hex_string(port_names[i]),
            'enabled': bool(enabled_mask & (1 << i)),
            'auto_negotiation': bool(auto_neg_mask & (1 << i)),
            'link_status': link_status_map.get(link_status[i], f'Unknown(0x{link_status[i]:02x})'),
            'link_up': bool(link_up_mask & (1 << i)),
            'full_duplex': bool(full_duplex_mask & (1 << i)),
            'uptime': uptime[i],
        })

    return ports


def get_poe(url, username, password):
    """Fetch and parse PoE information from poe.b

    Returns empty list if PoE is not supported by the switch.
    """
    auth = HTTPDigestAuth(username, password)
    try:
        response = requests.get(f"{url}/poe.b", auth=auth)
        response.raise_for_status()

        if not response.text or response.text.strip() == '':
            return []

        data = parse_js_object(response.text)
    except (requests.exceptions.HTTPError, ValueError, KeyError):
        # PoE not supported on this switch
        return []

    # PoE mode mapping
    poe_mode_map = {
        0x00: 'off',
        0x01: 'on',
        0x02: 'auto',
    }

    # PoE voltage level mapping
    voltage_level_map = {
        0x00: 'auto',
        0x01: 'low',
        0x02: 'high',
    }

    # PoE status mapping
    poe_status_map = {
        0x00: 'disabled',
        0x02: 'waiting for load',
        0x03: 'powered on',
        0x05: 'short circuit',
        0x06: 'overload',
    }

    poe_modes = data.get('i01', [])
    poe_priorities = data.get('i02', [])
    voltage_levels = data.get('i03', [])
    poe_status = data.get('i04', [])
    poe_current = data.get('i05', [])  # in mA
    poe_voltage = data.get('i06', [])  # in 0.1V
    poe_power = data.get('i07', [])    # in 0.1W
    lldp_enabled_mask = data.get('i08', 0)
    lldp_power = data.get('i0b', [])   # in 0.1W

    ports = []
    for i in range(len(poe_modes)):
        port_info = {
            'port_number': i + 1,
            'poe_mode': poe_mode_map.get(poe_modes[i], f'Unknown(0x{poe_modes[i]:02x})'),
            'poe_priority': poe_priorities[i] + 1,  # 0-based to 1-based
            'voltage_level': voltage_level_map.get(voltage_levels[i], f'Unknown(0x{voltage_levels[i]:02x})'),
            'poe_status': poe_status_map.get(poe_status[i], f'Unknown(0x{poe_status[i]:02x})'),
            'lldp_enabled': bool(lldp_enabled_mask & (1 << i)),
        }

        # Add current/voltage/power if PoE is active
        if poe_current[i] > 0:
            port_info['poe_current_ma'] = poe_current[i]
            port_info['poe_voltage_v'] = poe_voltage[i] / 10.0
            port_info['poe_power_w'] = poe_power[i] / 10.0

        # Add LLDP power if available
        if i < len(lldp_power) and lldp_power[i] > 0:
            port_info['lldp_power_w'] = lldp_power[i] / 10.0

        ports.append(port_info)

    return ports


def get_lag(url, username, password):
    """Fetch and parse LAG/LACP information from lacp.b

    Returns empty list if LAG/LACP is not supported by the switch.
    """
    auth = HTTPDigestAuth(username, password)
    try:
        response = requests.get(f"{url}/lacp.b", auth=auth)
        response.raise_for_status()

        if not response.text or response.text.strip() == '':
            return []

        data = parse_js_object(response.text)
    except (requests.exceptions.HTTPError, ValueError, KeyError):
        # LAG/LACP not supported on this switch
        return []

    # LACP mode mapping
    lacp_mode_map = {
        0x00: 'passive',
        0x01: 'active',
        0x02: 'static',
    }

    lacp_modes = data.get('i01', [])
    lacp_groups = data.get('i02', [])
    lacp_trunk = data.get('i03', [])
    lacp_partners = data.get('i04', [])

    ports = []
    for i in range(len(lacp_modes)):
        ports.append({
            'port_number': i + 1,
            'lacp_mode': lacp_mode_map.get(lacp_modes[i], f'Unknown(0x{lacp_modes[i]:02x})'),
            'lacp_group': lacp_groups[i],
            'lacp_trunk': lacp_trunk[i],
            'lacp_partner': lacp_partners[i] if i < len(lacp_partners) else '',
        })

    return ports


def get_sfp_info(url, username, password):
    """Fetch and parse SFP port information from sfp.b

    Returns empty dict if SFP ports are not available on the switch.
    """
    auth = HTTPDigestAuth(username, password)
    try:
        response = requests.get(f"{url}/sfp.b", auth=auth)
        response.raise_for_status()

        if not response.text or response.text.strip() == '':
            return {}

        data = parse_js_object(response.text)
        return data
    except (requests.exceptions.HTTPError, ValueError, KeyError):
        # SFP not supported on this switch
        return {}


def get_snmp(url, username, password):
    """Fetch and parse SNMP configuration from snmp.b

    Returns empty dict if SNMP is not supported by the switch.
    """
    auth = HTTPDigestAuth(username, password)
    try:
        response = requests.get(f"{url}/snmp.b", auth=auth)
        response.raise_for_status()

        if not response.text or response.text.strip() == '':
            return {}

        data = parse_js_object(response.text)

        return {
            'enabled': bool(data.get('i01', 0)),
            'community': decode_hex_string(data.get('i02', '')),
            'contact': decode_hex_string(data.get('i03', '')),
            'location': decode_hex_string(data.get('i04', '')),
        }
    except (requests.exceptions.HTTPError, ValueError, KeyError):
        # SNMP not supported on this switch
        return {}


def encode_hex_string(text):
    """Encode an ASCII string to hex for wire format"""
    return binascii.hexlify(text.encode('ascii')).decode('ascii')


def set_port_config(url, username, password, port_number, name=None, enabled=None, auto_negotiation=None):
    """
    Set port/link configuration for a specific port

    Args:
        url: Switch URL
        username: Username
        password: Password
        port_number: Port number (1-based)
        name: Port name (optional)
        enabled: Port enabled state - True/False (optional)
        auto_negotiation: Auto-negotiation enabled - True/False (optional)
    """
    auth = HTTPDigestAuth(username, password)

    # Get current port configuration
    current = get_links(url, username, password)
    port_idx = port_number - 1

    if port_idx >= len(current):
        raise ValueError(f"Invalid port number: {port_number}")

    # Build the update - we need to send all port configs
    response = requests.get(f"{url}/link.b", auth=auth)
    response.raise_for_status()
    data = parse_js_object(response.text)

    # Update the specific port
    if name is not None:
        data['i0a'][port_idx] = encode_hex_string(name)

    if enabled is not None:
        enabled_mask = data['i01']
        if enabled:
            enabled_mask |= (1 << port_idx)  # Set bit
        else:
            enabled_mask &= ~(1 << port_idx)  # Clear bit
        data['i01'] = enabled_mask

    if auto_negotiation is not None:
        auto_neg_mask = data['i02']
        if auto_negotiation:
            auto_neg_mask |= (1 << port_idx)  # Set bit
        else:
            auto_neg_mask &= ~(1 << port_idx)  # Clear bit
        data['i02'] = auto_neg_mask

    # Convert back to the wire format
    def to_hex(val):
        if isinstance(val, list):
            return '[' + ','.join(f'0x{v:04x}' if isinstance(v, int) else f"'{v}'" for v in val) + ']'
        return f'0x{val:04x}' if isinstance(val, int) else f"'{val}'"

    # Build POST body
    post_data = '{' + ','.join(f'{k}:{to_hex(v)}' for k, v in data.items()) + '}'

    # Send POST request
    response = requests.post(f"{url}/link.b", data=post_data, auth=auth,
                           headers={'Content-Type': 'application/x-www-form-urlencoded'})
    response.raise_for_status()
    return response.text


def set_poe_config(url, username, password, port_number, mode=None, priority=None, voltage_level=None, lldp_enabled=None):
    """
    Set PoE configuration for a specific port

    Args:
        url: Switch URL
        username: Username
        password: Password
        port_number: Port number (1-based)
        mode: PoE mode - 'off', 'on', 'auto' (optional)
        priority: PoE priority - 1-based priority (optional)
        voltage_level: Voltage level - 'auto', 'low', 'high' (optional)
        lldp_enabled: LLDP enabled state - True/False (optional)
    """
    auth = HTTPDigestAuth(username, password)

    # Get current PoE configuration
    current = get_poe(url, username, password)
    port_idx = port_number - 1

    if port_idx >= len(current):
        raise ValueError(f"Invalid port number: {port_number}")

    # Build the update - we need to send all port configs
    response = requests.get(f"{url}/poe.b", auth=auth)
    response.raise_for_status()
    data = parse_js_object(response.text)

    # Update the specific port
    if mode is not None:
        mode_map = {'off': 0x00, 'on': 0x01, 'auto': 0x02}
        data['i01'][port_idx] = mode_map[mode]

    if priority is not None:
        data['i02'][port_idx] = priority - 1  # Convert 1-based to 0-based

    if voltage_level is not None:
        voltage_map = {'auto': 0x00, 'low': 0x01, 'high': 0x02}
        data['i03'][port_idx] = voltage_map[voltage_level]

    if lldp_enabled is not None:
        lldp_mask = data.get('i08', 0)
        if lldp_enabled:
            lldp_mask |= (1 << port_idx)  # Set bit
        else:
            lldp_mask &= ~(1 << port_idx)  # Clear bit
        data['i08'] = lldp_mask

    # Convert back to the wire format
    def to_hex(val):
        if isinstance(val, list):
            return '[' + ','.join(f'0x{v:04x}' if isinstance(v, int) else f"'{v}'" for v in val) + ']'
        return f'0x{val:04x}' if isinstance(val, int) else f"'{val}'"

    # Build POST body
    post_data = '{' + ','.join(f'{k}:{to_hex(v)}' for k, v in data.items()) + '}'

    # Send POST request
    response = requests.post(f"{url}/poe.b", data=post_data, auth=auth,
                           headers={'Content-Type': 'application/x-www-form-urlencoded'})
    response.raise_for_status()
    return response.text


def set_lag_config(url, username, password, port_number, mode=None, group=None):
    """
    Set LAG/LACP configuration for a specific port

    Args:
        url: Switch URL
        username: Username
        password: Password
        port_number: Port number (1-based)
        mode: LACP mode - 'passive', 'active', 'static' (optional)
        group: LAG group number (optional)
    """
    auth = HTTPDigestAuth(username, password)

    # Get current LAG configuration
    current = get_lag(url, username, password)
    port_idx = port_number - 1

    if port_idx >= len(current):
        raise ValueError(f"Invalid port number: {port_number}")

    # Build the update - we need to send all port configs
    response = requests.get(f"{url}/lacp.b", auth=auth)
    response.raise_for_status()
    data = parse_js_object(response.text)

    # Update the specific port
    if mode is not None:
        mode_map = {'passive': 0x00, 'active': 0x01, 'static': 0x02}
        data['i01'][port_idx] = mode_map[mode]

    if group is not None:
        data['i02'][port_idx] = group

    # Convert back to the wire format
    def to_hex(val):
        if isinstance(val, list):
            return '[' + ','.join(f'0x{v:04x}' if isinstance(v, int) else f"'{v}'" for v in val) + ']'
        return f'0x{val:04x}' if isinstance(val, int) else f"'{val}'"

    # Build POST body
    post_data = '{' + ','.join(f'{k}:{to_hex(v)}' for k, v in data.items()) + '}'

    # Send POST request
    response = requests.post(f"{url}/lacp.b", data=post_data, auth=auth,
                           headers={'Content-Type': 'application/x-www-form-urlencoded'})
    response.raise_for_status()
    return response.text


def set_port_vlan(url, username, password, port_number, vlan_mode=None, vlan_receive=None, default_vlan_id=None):
    """
    Set VLAN configuration for a specific port

    Args:
        url: Switch URL
        username: Username
        password: Password
        port_number: Port number (1-based)
        vlan_mode: VLAN mode - 'Disabled', 'Optional', 'Enabled', 'Strict' (optional)
        vlan_receive: Receive mode - 'Any', 'Only Tagged', 'Only Untagged' (optional)
        default_vlan_id: Default VLAN ID (optional)
    """
    auth = HTTPDigestAuth(username, password)

    # Get current VLAN configuration
    current = get_port_vlans(url, username, password)
    port_idx = port_number - 1

    if port_idx >= len(current):
        raise ValueError(f"Invalid port number: {port_number}")

    # Build the update - we need to send all port configs
    response = requests.get(f"{url}/fwd.b", auth=auth)
    response.raise_for_status()
    data = parse_js_object(response.text)

    # Update the specific port
    if vlan_mode is not None:
        mode_map = {'Disabled': 0, 'Optional': 1, 'Enabled': 2, 'Strict': 3}
        data['i15'][port_idx] = mode_map[vlan_mode]

    if vlan_receive is not None:
        receive_map = {'Any': 0, 'Only Tagged': 1, 'Only Untagged': 2}
        data['i17'][port_idx] = receive_map[vlan_receive]

    if default_vlan_id is not None:
        data['i18'][port_idx] = default_vlan_id

    # Convert back to the wire format
    def to_hex(val):
        if isinstance(val, list):
            return '[' + ','.join(f'0x{v:04x}' if isinstance(v, int) else f"'{v}'" for v in val) + ']'
        return f'0x{val:04x}' if isinstance(val, int) else f"'{val}'"

    # Build POST body
    post_data = '{' + ','.join(f'{k}:{to_hex(v)}' for k, v in data.items()) + '}'

    # Send POST request
    response = requests.post(f"{url}/fwd.b", data=post_data, auth=auth,
                           headers={'Content-Type': 'application/x-www-form-urlencoded'})
    response.raise_for_status()
    return response.text


def set_snmp(url, username, password, enabled=None, community=None, contact=None, location=None):
    """
    Set SNMP configuration

    Args:
        url: Switch URL
        username: Username
        password: Password
        enabled: SNMP enabled state - True/False (optional)
        community: Community string (optional)
        contact: Contact information (optional)
        location: Device location (optional)
    """
    auth = HTTPDigestAuth(username, password)

    # Get current SNMP configuration
    response = requests.get(f"{url}/snmp.b", auth=auth)
    response.raise_for_status()
    data = parse_js_object(response.text)

    # Update fields
    if enabled is not None:
        data['i01'] = 0x01 if enabled else 0x00

    if community is not None:
        data['i02'] = encode_hex_string(community)

    if contact is not None:
        data['i03'] = encode_hex_string(contact)

    if location is not None:
        data['i04'] = encode_hex_string(location)

    # Convert back to the wire format
    def to_hex(val):
        if isinstance(val, list):
            return '[' + ','.join(f'0x{v:04x}' if isinstance(v, int) else f"'{v}'" for v in val) + ']'
        return f'0x{val:04x}' if isinstance(val, int) else f"'{val}'"

    # Build POST body
    post_data = '{' + ','.join(f'{k}:{to_hex(v)}' for k, v in data.items()) + '}'

    # Send POST request
    response = requests.post(f"{url}/snmp.b", data=post_data, auth=auth,
                           headers={'Content-Type': 'application/x-www-form-urlencoded'})
    response.raise_for_status()
    return response.text


if __name__ == '__main__':
    # Test the parser
    import sys

    if len(sys.argv) < 3:
        print("Usage: python swos_lite_api.py <switch_ip> <username> [password]")
        sys.exit(1)

    switch_ip = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3] if len(sys.argv) > 3 else ''

    if not switch_ip.startswith('http'):
        switch_url = f"http://{switch_ip}"
    else:
        switch_url = switch_ip

    print("System Info:")
    print(get_system_info(switch_url, username, password))

    print("\nLink/Port Info:")
    for port in get_links(switch_url, username, password):
        print(f"  Port {port['port_number']} ({port['port_name']}): {port['link_status']}, Enabled={port['enabled']}, Auto-neg={port['auto_negotiation']}")

    print("\nPoE Info:")
    for port in get_poe(switch_url, username, password):
        poe_info = f"  Port {port['port_number']}: Mode={port['poe_mode']}, Priority={port['poe_priority']}, Status={port['poe_status']}"
        if 'poe_power_w' in port:
            poe_info += f", Power={port['poe_power_w']:.1f}W"
        print(poe_info)

    print("\nLAG/LACP Info:")
    for port in get_lag(switch_url, username, password):
        print(f"  Port {port['port_number']}: Mode={port['lacp_mode']}, Group={port['lacp_group']}")

    print("\nVLANs:")
    for vlan in get_vlans(switch_url, username, password):
        ports = decode_port_mask(vlan['port_mask'])
        print(f"  VLAN {vlan['vlan_id']}: Ports {ports}")

    print("\nPort VLAN Config:")
    for port in get_port_vlans(switch_url, username, password):
        print(f"  Port {port['port_number']}: {port['vlan_mode']}, Receive={port['vlan_receive']}, Default VLAN={port['default_vlan_id']}")
