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
    """Fetch and parse system information from sys.b

    Returns both read-only and writable system settings:
    - Read-only: mac_address, serial_number, version, model, uptime
    - Writable: identity, address_acquisition, static_ip, allow_from, allow_from_ports, allow_from_vlan
    """
    auth = HTTPDigestAuth(username, password)
    response = requests.get(f"{url}/sys.b", auth=auth)
    response.raise_for_status()

    data = parse_js_object(response.text)

    # Parse address acquisition mode
    addr_acq_map = {
        0x00: 'DHCP with fallback',
        0x01: 'static',
        0x02: 'DHCP only',
    }
    addr_acq_mode = data.get('i0a', 0)

    # Parse Allow From (IP + netmask bits)
    allow_from_ip = data.get('i19', 0)
    allow_from_bits = data.get('i1a', 0)

    # Convert IP from hex to dotted notation
    # SwOS uses little-endian: 192.168.88.1 stored as 0x0158a8c0
    # LSB (0x01) = first octet, MSB (0xc0) = last octet
    if allow_from_ip:
        allow_from_str = f"{allow_from_ip & 0xFF}.{(allow_from_ip >> 8) & 0xFF}.{(allow_from_ip >> 16) & 0xFF}.{(allow_from_ip >> 24) & 0xFF}"
        if allow_from_bits > 0:
            allow_from_str += f"/{allow_from_bits}"
    else:
        allow_from_str = ""

    # Parse static IP (little-endian format)
    static_ip_val = data.get('i09', 0)
    static_ip_str = f"{static_ip_val & 0xFF}.{(static_ip_val >> 8) & 0xFF}.{(static_ip_val >> 16) & 0xFF}.{(static_ip_val >> 24) & 0xFF}"

    # Decode allow_from_ports bitmask to list
    allow_from_ports = decode_port_mask(data.get('i12', 0), num_ports=10)

    return {
        # Read-only fields
        'mac_address': decode_mac_address(data.get('i03', '')),
        'serial_number': decode_hex_string(data.get('i04', '')),
        'version': decode_hex_string(data.get('i06', '')),
        'model': decode_hex_string(data.get('i07', '')),
        'uptime': data.get('i01', 0),

        # Writable fields
        'identity': decode_hex_string(data.get('i05', '')),
        'address_acquisition': addr_acq_map.get(addr_acq_mode, f'Unknown({addr_acq_mode})'),
        'static_ip': static_ip_str,
        'allow_from': allow_from_str,
        'allow_from_ports': allow_from_ports,
        'allow_from_vlan': data.get('i1b', 1),
    }


def get_vlans(url, username, password):
    """Fetch and parse VLAN configuration from vlan.b

    Returns a list of VLANs with:
    - vlan_id: VLAN ID (1-4094)
    - member_ports: List of port numbers (1-10)
    - igmp_snooping: IGMP snooping enabled (boolean)
    """
    auth = HTTPDigestAuth(username, password)
    response = requests.get(f"{url}/vlan.b", auth=auth)
    response.raise_for_status()

    data = parse_js_object(response.text)

    vlans = []
    for vlan in data:
        vlan_id = vlan.get('i01', 0)
        port_mask = vlan.get('i02', 0)
        igmp_snooping = bool(vlan.get('i03', 0))

        # Decode port mask to list of port numbers
        member_ports = decode_port_mask(port_mask, num_ports=10)

        vlans.append({
            'vlan_id': vlan_id,
            'member_ports': member_ports,
            'igmp_snooping': igmp_snooping,
        })

    return vlans


def get_port_vlans(url, username, password):
    """Fetch and parse per-port VLAN configuration from fwd.b"""
    auth = HTTPDigestAuth(username, password)
    response = requests.get(f"{url}/fwd.b", auth=auth)
    response.raise_for_status()

    data = parse_js_object(response.text)

    # VLAN mode mapping (from engine.js: disabled, optional, strict)
    vlan_modes = {
        0: 'Disabled',
        1: 'Optional',
        2: 'Strict',
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
    force_vlan_mask = data.get('i19', 0)

    ports = []
    for i in range(len(modes)):
        ports.append({
            'port_number': i + 1,
            'vlan_mode': vlan_modes.get(modes[i], f'Unknown({modes[i]})'),
            'vlan_receive': receive_modes.get(receive[i], f'Unknown({receive[i]})'),
            'default_vlan_id': default_vlans[i],
            'force_vlan_id': bool(force_vlan_mask & (1 << i)),
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
    lldp_enabled_mask = data.get('i0a', 0)  # Changed from i08 to i0a
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


def _format_hex_value(val):
    """
    Format a hex value for POST request (match browser JavaScript logic)

    Browser's Ha() function converts numbers to hex with even-length padding:
    - Converts to hex string
    - If odd length, prepends '0' to make it even
    - Adds '0x' prefix

    Examples:
        0 → "0x00"
        0xff → "0x00ff"
        0x3ff → "0x03ff"
        0x3bf → "0x03bf"
    """
    hex_str = f'{val:x}'
    if len(hex_str) % 2 == 1:
        hex_str = '0' + hex_str
    return f'0x{hex_str}'


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

    # Convert back to the wire format (match browser JavaScript format exactly)
    def to_hex(val):
        if isinstance(val, list):
            # For arrays: use 2-digit hex for ints, strings stay as-is
            return '[' + ','.join(f'0x{v:02x}' if isinstance(v, int) else f"'{v}'" for v in val) + ']'
        elif isinstance(val, int):
            # For scalars/bitmasks: use even-length hex (browser's Ha() function logic)
            return _format_hex_value(val)
        else:
            return f"'{val}'"

    # Build POST body - only send writable fields (match browser behavior)
    # Browser sends: i01 (enabled), i0a (names), i02 (auto_neg), i05 (speed), i03 (duplex), i16 (flow_tx), i12 (flow_rx)
    writable_data = {
        'i01': data['i01'],  # Enabled bitmask
        'i0a': data['i0a'],  # Port names array
        'i02': data['i02'],  # Auto-negotiation bitmask
        'i05': data['i05'],  # Speed array
        'i03': data['i03'],  # Full duplex bitmask
        'i16': data['i16'],  # Flow Control Tx bitmask
        'i12': data['i12']   # Flow Control Rx bitmask
    }
    post_data = '{' + ','.join(f'{k}:{to_hex(v)}' for k, v in writable_data.items()) + '}'

    # Send POST request (use text/plain like browser does)
    response = requests.post(f"{url}/link.b", data=post_data, auth=auth,
                           headers={'Content-Type': 'text/plain'})
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
        lldp_mask = data.get('i0a', 0)  # Changed from i08 to i0a
        # LLDP field (i0a) is an 8-bit bitmask for PoE ports (hardcoded as j:8 in engine.js)
        # CSS610-8P-2S+ has 8 PoE-capable ports (ports 1-8), SFP+ ports don't support PoE
        MAX_POE_PORTS = 8
        if port_idx >= MAX_POE_PORTS:
            raise ValueError(f"Port {port_number} does not support PoE LLDP (only ports 1-{MAX_POE_PORTS} support PoE/LLDP)")

        if lldp_enabled:
            lldp_mask |= (1 << port_idx)  # Set bit
        else:
            lldp_mask &= ~(1 << port_idx)  # Clear bit
        data['i0a'] = lldp_mask  # Changed from i08 to i0a

    # Convert back to the wire format (match browser: 2-digit hex for arrays, minimal for scalars)
    def to_hex(val):
        if isinstance(val, list):
            return '[' + ','.join(f'0x{v:02x}' for v in val) + ']'
        return _format_hex_value(val)

    # Build POST body - only send writable fields for PoE ports (first 8 ports)
    # Browser only sends: i01 (mode), i02 (priority), i03 (voltage), i0a (lldp)
    # Only include first 8 elements for arrays (PoE-capable ports)
    writable_data = {
        'i01': data['i01'][:8],  # PoE mode
        'i02': data['i02'][:8],  # PoE priority
        'i03': data['i03'][:8],  # Voltage level
        'i0a': data['i0a']       # LLDP bitmask
    }
    post_data = '{' + ','.join(f'{k}:{to_hex(v)}' for k, v in writable_data.items()) + '}'

    # Send POST request (use text/plain like browser does)
    response = requests.post(f"{url}/poe.b", data=post_data, auth=auth,
                           headers={'Content-Type': 'text/plain'})
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
        data['i03'][port_idx] = group

    # Convert back to the wire format (match browser JavaScript format exactly)
    def to_hex(val):
        if isinstance(val, list):
            # For arrays: use 2-digit hex for ints, strings stay as-is
            return '[' + ','.join(f'0x{v:02x}' if isinstance(v, int) else f"'{v}'" for v in val) + ']'
        elif isinstance(val, int):
            # For scalars/bitmasks: use even-length hex (browser's Ha() function logic)
            return _format_hex_value(val)
        else:
            return f"'{val}'"

    # Build POST body - only send writable fields (match browser behavior)
    # Browser sends: i01 (mode), i03 (group)
    writable_data = {
        'i01': data['i01'],  # Mode array
        'i03': data['i03']   # Group array
    }
    post_data = '{' + ','.join(f'{k}:{to_hex(v)}' for k, v in writable_data.items()) + '}'

    # Send POST request (use text/plain like browser does)
    response = requests.post(f"{url}/lacp.b", data=post_data, auth=auth,
                           headers={'Content-Type': 'text/plain'})
    response.raise_for_status()
    return response.text


def set_port_vlan(url, username, password, port_number, vlan_mode=None, vlan_receive=None, default_vlan_id=None, force_vlan_id=None):
    """
    Set VLAN configuration for a specific port

    Args:
        url: Switch URL
        username: Username
        password: Password
        port_number: Port number (1-based)
        vlan_mode: VLAN mode - 'Disabled', 'Optional', 'Strict' (optional)
        vlan_receive: Receive mode - 'Any', 'Only Tagged', 'Only Untagged' (optional)
        default_vlan_id: Default VLAN ID (optional)
        force_vlan_id: Force VLAN ID - True/False (optional)
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
        # VLAN Mode: disabled=0, optional=1, strict=2 (from engine.js)
        mode_map = {'Disabled': 0, 'Optional': 1, 'Strict': 2}
        data['i15'][port_idx] = mode_map[vlan_mode]

    if vlan_receive is not None:
        receive_map = {'Any': 0, 'Only Tagged': 1, 'Only Untagged': 2}
        data['i17'][port_idx] = receive_map[vlan_receive]

    if default_vlan_id is not None:
        data['i18'][port_idx] = default_vlan_id

    if force_vlan_id is not None:
        force_mask = data['i19']
        if force_vlan_id:
            force_mask |= (1 << port_idx)  # Set bit
        else:
            force_mask &= ~(1 << port_idx)  # Clear bit
        data['i19'] = force_mask

    # Convert back to the wire format (match browser JavaScript format exactly)
    def to_hex(val):
        if isinstance(val, list):
            # For arrays: use 2-digit hex for ints, strings stay as-is
            return '[' + ','.join(f'0x{v:02x}' if isinstance(v, int) else f"'{v}'" for v in val) + ']'
        elif isinstance(val, int):
            # For scalars/bitmasks: use even-length hex (browser's Ha() function logic)
            return _format_hex_value(val)
        else:
            return f"'{val}'"

    # Build POST body - only send writable fields (match browser behavior)
    # Browser sends: i15 (vlan_mode), i17 (vlan_receive), i18 (default_vlan_id), i19 (force_vlan_id)
    writable_data = {
        'i15': data['i15'],  # VLAN mode array
        'i17': data['i17'],  # VLAN receive array
        'i18': data['i18'],  # Default VLAN ID array
        'i19': data['i19']   # Force VLAN ID bitmask
    }
    post_data = '{' + ','.join(f'{k}:{to_hex(v)}' for k, v in writable_data.items()) + '}'

    # Send POST request (use text/plain like browser does)
    response = requests.post(f"{url}/fwd.b", data=post_data, auth=auth,
                           headers={'Content-Type': 'text/plain'})
    response.raise_for_status()
    return response.text


def set_vlans(url, username, password, vlans):
    """Set VLAN table configuration via vlan.b

    Args:
        url: Switch URL
        username: Admin username
        password: Admin password
        vlans: List of VLAN dictionaries with:
            - vlan_id: VLAN ID (1-4094, required)
            - member_ports: List of port numbers (1-10, required)
            - igmp_snooping: IGMP snooping enabled (boolean, optional, defaults to False)

    Example:
        vlans = [
            {'vlan_id': 1, 'member_ports': [1, 2, 3, 4]},
            {'vlan_id': 10, 'member_ports': [5, 6], 'igmp_snooping': True},
        ]
        set_vlans(url, username, password, vlans)
    """
    auth = HTTPDigestAuth(username, password)

    # Build VLAN array in vlan.b format
    vlan_array = []
    for vlan in vlans:
        vlan_id = vlan['vlan_id']
        member_ports = vlan['member_ports']
        igmp_snooping = vlan.get('igmp_snooping', False)

        # Validate VLAN ID
        if not (1 <= vlan_id <= 4094):
            raise ValueError(f"VLAN ID must be between 1 and 4094, got {vlan_id}")

        # Convert member_ports list to bitmask
        port_mask = 0
        for port_num in member_ports:
            if not (1 <= port_num <= 10):
                raise ValueError(f"Port number must be between 1 and 10, got {port_num}")
            port_mask |= (1 << (port_num - 1))

        vlan_array.append({
            'i01': vlan_id,
            'i02': port_mask,
            'i03': 0x01 if igmp_snooping else 0x00,
        })

    # Convert to wire format (array of objects)
    def to_hex(val):
        if isinstance(val, int):
            return _format_hex_value(val)
        else:
            return f"'{val}'"

    # Build array string
    vlan_strings = []
    for vlan_obj in vlan_array:
        pairs = [f'{k}:{to_hex(v)}' for k, v in vlan_obj.items()]
        vlan_strings.append('{' + ','.join(pairs) + '}')

    post_data = '[' + ','.join(vlan_strings) + ']'

    # Send POST request (use text/plain like browser does)
    response = requests.post(f"{url}/vlan.b", data=post_data, auth=auth,
                           headers={'Content-Type': 'text/plain'})
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

    # Convert back to the wire format (match browser JavaScript format exactly)
    def to_hex(val):
        if isinstance(val, list):
            # For arrays: use 2-digit hex for ints, strings stay as-is
            return '[' + ','.join(f'0x{v:02x}' if isinstance(v, int) else f"'{v}'" for v in val) + ']'
        elif isinstance(val, int):
            # For scalars/bitmasks: use even-length hex (browser's Ha() function logic)
            return _format_hex_value(val)
        else:
            return f"'{val}'"

    # Build POST body - send all fields (SNMP has only 4 fields, all writable)
    # Fields: i01 (enabled), i02 (community), i03 (contact), i04 (location)
    post_data = '{' + ','.join(f'{k}:{to_hex(v)}' for k, v in data.items()) + '}'

    # Send POST request (use text/plain like browser does)
    response = requests.post(f"{url}/snmp.b", data=post_data, auth=auth,
                           headers={'Content-Type': 'text/plain'})
    response.raise_for_status()
    return response.text


def set_system(url, username, password, identity=None, address_acquisition=None, static_ip=None,
               allow_from=None, allow_from_ports=None, allow_from_vlan=None):
    """
    Set system configuration

    Args:
        url: Switch URL
        username: Username
        password: Password
        identity: Device identity/name (optional)
        address_acquisition: Address mode - "DHCP with fallback", "static", or "DHCP only" (optional)
        static_ip: Static IP address as string (e.g., "192.168.88.1") (optional)
        allow_from: IP/CIDR for management access (e.g., "192.168.1.0/24" or "") (optional)
        allow_from_ports: List of port numbers allowed for management access (e.g., [1, 2, 9, 10]) (optional)
        allow_from_vlan: VLAN ID allowed for management access (1-4095) (optional)
    """
    auth = HTTPDigestAuth(username, password)

    # Get current system configuration
    response = requests.get(f"{url}/sys.b", auth=auth)
    response.raise_for_status()
    data = parse_js_object(response.text)

    # Update identity
    if identity is not None:
        data['i05'] = encode_hex_string(identity)

    # Update address acquisition mode
    if address_acquisition is not None:
        addr_acq_map = {
            'DHCP with fallback': 0x00,
            'static': 0x01,
            'DHCP only': 0x02,
        }
        if address_acquisition not in addr_acq_map:
            raise ValueError(f"address_acquisition must be one of {list(addr_acq_map.keys())}, got '{address_acquisition}'")
        data['i0a'] = addr_acq_map[address_acquisition]

    # Update static IP
    if static_ip is not None:
        parts = static_ip.split('.')
        if len(parts) != 4:
            raise ValueError(f"static_ip must be in dotted notation (e.g., '192.168.88.1'), got '{static_ip}'")
        try:
            # Encode as little-endian: parts[0] (192) in LSB
            # For 192.168.88.1: 192 | (168 << 8) | (88 << 16) | (1 << 24) = 0x0158a8c0
            ip_int = int(parts[0]) | (int(parts[1]) << 8) | (int(parts[2]) << 16) | (int(parts[3]) << 24)
            data['i09'] = ip_int
        except ValueError:
            raise ValueError(f"Invalid IP address '{static_ip}'")

    # Update Allow From (IP/CIDR)
    if allow_from is not None:
        if allow_from == "":
            # Empty string means no restriction
            data['i19'] = 0x00000000
            data['i1a'] = 0x00
        else:
            # Parse IP/CIDR
            if '/' in allow_from:
                ip_part, bits_part = allow_from.split('/')
                bits = int(bits_part)
                if not (0 <= bits <= 32):
                    raise ValueError(f"CIDR bits must be 0-32, got {bits}")
            else:
                ip_part = allow_from
                bits = 32

            parts = ip_part.split('.')
            if len(parts) != 4:
                raise ValueError(f"allow_from IP must be in dotted notation, got '{ip_part}'")
            try:
                # Encode as little-endian: parts[0] in LSB
                ip_int = int(parts[0]) | (int(parts[1]) << 8) | (int(parts[2]) << 16) | (int(parts[3]) << 24)
                data['i19'] = ip_int
                data['i1a'] = bits
            except ValueError:
                raise ValueError(f"Invalid IP address in allow_from '{ip_part}'")

    # Update Allow From Ports (list to bitmask)
    if allow_from_ports is not None:
        port_mask = 0
        for port_num in allow_from_ports:
            if not (1 <= port_num <= 10):
                raise ValueError(f"Port number must be between 1 and 10, got {port_num}")
            port_mask |= (1 << (port_num - 1))
        data['i12'] = port_mask

    # Update Allow From VLAN
    if allow_from_vlan is not None:
        if not (1 <= allow_from_vlan <= 4095):
            raise ValueError(f"allow_from_vlan must be between 1 and 4095, got {allow_from_vlan}")
        data['i1b'] = allow_from_vlan

    # Convert back to the wire format (match browser JavaScript format exactly)
    def to_hex(val):
        if isinstance(val, list):
            # For arrays: use 2-digit hex for ints, strings stay as-is
            return '[' + ','.join(f'0x{v:02x}' if isinstance(v, int) else f"'{v}'" for v in val) + ']'
        elif isinstance(val, int):
            # For scalars/bitmasks: use even-length hex (browser's Ha() function logic)
            return _format_hex_value(val)
        else:
            return f"'{val}'"

    # Build POST body - send all fields
    # Writable fields: i05 (identity), i0a (addr_acq), i09 (static_ip), i19+i1a (allow_from), i12 (allow_from_ports), i1b (allow_from_vlan)
    # Note: Browser sends all fields, so we do the same
    post_data = '{' + ','.join(f'{k}:{to_hex(v)}' for k, v in data.items()) + '}'

    # Send POST request (use text/plain like browser does)
    response = requests.post(f"{url}/sys.b", data=post_data, auth=auth,
                           headers={'Content-Type': 'text/plain'})
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
