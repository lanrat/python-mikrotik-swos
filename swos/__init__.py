#!/usr/bin/env python3
"""
SwOS/SwOS Lite API Library

Python library for MikroTik SwOS and SwOS Lite switches.

Supports:
- SwOS Lite (CSS series): CSS610-8G-2S+, CSS610-8P-2S+, CSS326-24G-2S+, etc.
- SwOS (CRS/RB series): CRS305-1G-4S+, CRS310-8G+2S+, CRS328-24P-4S+, etc.

Platform is automatically detected - no configuration required.

Read Operations:
    System info, ports, PoE, LAG/LACP, VLANs, host table, SFP info, SNMP

Write Operations:
    Port config, PoE settings, LAG/LACP, per-port VLANs, SNMP

Example:
    >>> from swos import get_system_info, set_port_config
    >>>
    >>> system = get_system_info('http://192.168.88.1', 'admin', '')
    >>> print(f"{system['identity']} - {system['model']}")
    >>>
    >>> set_port_config('http://192.168.88.1', 'admin', '',
    >>>                 port_number=1, name='Uplink')

Authentication: HTTP Digest (username/password)
Requirements: requests>=2.25.0
Compatibility: SwOS 2.14+, SwOS Lite 2.17+
"""

import requests
from requests.auth import HTTPDigestAuth
from typing import Optional, List, Dict, Any

# Import core modules
from .core import (
    parse_js_object,
    decode_hex_string,
    encode_hex_string,
    decode_mac_address,
    encode_mac_address,
    decode_ip_address_le,
    encode_ip_address_le,
    decode_port_mask,
    encode_port_mask,
    build_post_data,
    build_post_array,
)
from .platform import PlatformAdapter, PlatformType, detect_platform
from .field_maps import get_field

# Module-level adapter cache to avoid re-detecting platform on every call
_adapter_cache: Dict[tuple, PlatformAdapter] = {}


def _get_adapter(url: str, username: str, password: str) -> PlatformAdapter:
    """
    Get or create platform adapter (cached by URL/credentials)

    Args:
        url: Switch URL
        username: Username
        password: Password

    Returns:
        PlatformAdapter instance (cached)
    """
    cache_key = (url.rstrip('/'), username, password)
    if cache_key not in _adapter_cache:
        _adapter_cache[cache_key] = PlatformAdapter(url, username, password)
    return _adapter_cache[cache_key]


def get_system_info(url: str, username: str, password: str) -> dict:
    """
    Fetch and parse system information

    Works for both SwOS and SwOS Lite. Platform is auto-detected.

    Args:
        url: Switch URL (e.g., 'http://192.168.88.1')
        username: Username for authentication
        password: Password for authentication

    Returns:
        dict with system information:
        - identity: Device name
        - mac_address: MAC address
        - serial_number: Serial number
        - version: Firmware version
        - model: Device model
        - uptime: Uptime in seconds
        - address_acquisition: 'static', 'DHCP with fallback', or 'DHCP only'
        - static_ip: Static IP address
        - allow_from: Management access restriction (IP/CIDR or empty)
        - allow_from_ports: List of ports allowed for management
        - allow_from_vlan: VLAN ID for management access
    """
    adapter = _get_adapter(url, username, password)
    data = adapter.get('system')
    fm = adapter.field_map

    # Parse address acquisition mode
    addr_acq_map = {
        0x00: 'DHCP with fallback',
        0x01: 'static',
        0x02: 'DHCP only',
    }
    addr_acq_mode = get_field(data, fm, 'system_address_acquisition') or 0

    # Parse Allow From (IP + netmask bits)
    allow_from_ip = get_field(data, fm, 'system_allow_from_ip') or 0
    allow_from_bits = get_field(data, fm, 'system_allow_from_bits') or 0

    if allow_from_ip:
        allow_from_str = decode_ip_address_le(allow_from_ip)
        if allow_from_bits > 0:
            allow_from_str += f"/{allow_from_bits}"
    else:
        allow_from_str = ""

    # Parse static IP
    static_ip_val = get_field(data, fm, 'system_static_ip') or 0
    static_ip_str = decode_ip_address_le(static_ip_val)

    # Decode allow_from_ports bitmask
    allow_from_ports_mask = get_field(data, fm, 'system_allow_from_ports') or 0
    allow_from_ports = decode_port_mask(allow_from_ports_mask, adapter.get_port_count())

    # Parse current IP
    current_ip_val = get_field(data, fm, 'system_current_ip') or 0
    current_ip_str = decode_ip_address_le(current_ip_val) if current_ip_val else ''

    return {
        # Read-only fields
        'mac_address': decode_mac_address(get_field(data, fm, 'system_mac') or ''),
        'serial_number': decode_hex_string(get_field(data, fm, 'system_serial') or ''),
        'version': decode_hex_string(get_field(data, fm, 'system_version') or ''),
        'model': decode_hex_string(get_field(data, fm, 'system_model') or ''),
        'uptime': get_field(data, fm, 'system_uptime') or 0,
        'current_ip': current_ip_str,

        # Writable fields
        'identity': decode_hex_string(get_field(data, fm, 'system_identity') or ''),
        'address_acquisition': addr_acq_map.get(addr_acq_mode, f'Unknown({addr_acq_mode})'),
        'static_ip': static_ip_str,
        'allow_from': allow_from_str,
        'allow_from_ports': allow_from_ports,
        'allow_from_vlan': get_field(data, fm, 'system_allow_from_vlan') or 1,
    }


def get_vlans(url: str, username: str, password: str) -> List[dict]:
    """
    Fetch and parse VLAN table configuration

    Args:
        url: Switch URL
        username: Username
        password: Password

    Returns:
        List of VLAN dicts:
        - vlan_id: VLAN ID (1-4094)
        - member_ports: List of port numbers in this VLAN
        - igmp_snooping: IGMP snooping enabled (boolean)
    """
    adapter = _get_adapter(url, username, password)
    data = adapter.get('vlan_table')
    fm = adapter.field_map
    port_count = adapter.get_port_count()

    # Handle array response
    if not isinstance(data, list):
        return []

    vlans = []
    for vlan in data:
        vlan_id = get_field(vlan, fm, 'vlan_id') or 0
        port_mask = get_field(vlan, fm, 'vlan_members') or 0
        igmp_snooping = bool(get_field(vlan, fm, 'vlan_igmp') or 0)

        # Decode port mask to list
        member_ports = decode_port_mask(port_mask, port_count)

        vlans.append({
            'vlan_id': vlan_id,
            'member_ports': member_ports,
            'igmp_snooping': igmp_snooping,
        })

    return vlans


def get_port_vlans(url: str, username: str, password: str) -> List[dict]:
    """
    Fetch and parse per-port VLAN configuration

    Args:
        url: Switch URL
        username: Username
        password: Password

    Returns:
        List of per-port VLAN configs:
        - port_number: Port number (1-based)
        - vlan_mode: 'Disabled', 'Optional', or 'Strict'
        - vlan_receive: 'Any', 'Only Tagged', or 'Only Untagged'
        - default_vlan_id: Default VLAN ID for untagged packets
        - force_vlan_id: Force default VLAN (boolean)
    """
    adapter = _get_adapter(url, username, password)
    data = adapter.get('vlan_port')
    fm = adapter.field_map

    # VLAN mode mapping
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

    modes = get_field(data, fm, 'vlan_port_mode') or []
    receive = get_field(data, fm, 'vlan_port_receive') or []
    default_vlans = get_field(data, fm, 'vlan_port_default_id') or []
    force_vlan_mask = get_field(data, fm, 'vlan_port_force_id') or 0

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


def get_hosts(url: str, username: str, password: str) -> List[dict]:
    """
    Fetch and parse learned MAC addresses from host table

    Args:
        url: Switch URL
        username: Username
        password: Password

    Returns:
        List of learned hosts:
        - mac_address: MAC address
        - port_number: Port number (1-based)
    """
    adapter = _get_adapter(url, username, password)
    auth = adapter.auth

    try:
        response = requests.get(f"{adapter.url}/!dhost.b", auth=auth, timeout=10, verify=False)
        response.raise_for_status()
        data = parse_js_object(response.text)
    except:
        return []

    # Parse host table - array of {i01: 'mac_hex', i02: port_index} for SwOS Lite
    # (SwOS format may differ - need to verify)
    hosts = []
    if isinstance(data, list):
        for host in data:
            # Try SwOS Lite format first
            mac_hex = host.get('i01', '')
            port_index = host.get('i02', 0)

            if mac_hex:
                # Format MAC address with colons
                mac_address = ':'.join(mac_hex[i:i+2] for i in range(0, len(mac_hex), 2))

                hosts.append({
                    'mac_address': mac_address,
                    'port_number': port_index + 1,  # Convert 0-based to 1-based
                })

    return hosts


def get_links(url: str, username: str, password: str) -> List[dict]:
    """
    Fetch and parse port/link information

    Args:
        url: Switch URL
        username: Username
        password: Password

    Returns:
        List of port configs:
        - port_number: Port number (1-based)
        - port_name: Port name
        - enabled: Port enabled (boolean)
        - auto_negotiation: Auto-negotiation enabled (boolean)
        - link_status: 'link on', 'no link', or status string
        - link_up: Link is up (boolean)
        - full_duplex: Full duplex mode (boolean)
        - uptime: Port uptime in seconds (SwOS Lite only)
    """
    adapter = _get_adapter(url, username, password)
    data = adapter.get('link')
    fm = adapter.field_map

    port_names = get_field(data, fm, 'port_names') or []
    enabled_mask = get_field(data, fm, 'port_enabled') or 0
    auto_neg_mask = get_field(data, fm, 'port_auto_neg') or 0
    link_up_mask = get_field(data, fm, 'port_link_up') or 0
    full_duplex_mask = get_field(data, fm, 'port_duplex_status') or 0
    speed_array = get_field(data, fm, 'port_speed') or []

    # Link status handling differs between platforms
    link_status_array = get_field(data, fm, 'port_link_status')  # SwOS Lite uses array
    uptime_array = get_field(data, fm, 'port_uptime')  # SwOS Lite only

    # SwOS Lite link status mapping
    link_status_map = {
        0x02: 'link on',
        0x07: 'no link',
    }

    # Speed mapping (confirmed codes from real devices: CRS305, CRS326, CSS610)
    # 0x03=1G, 0x05=2.5G, 0x07=10G confirmed
    speed_map = {
        0: 'down',
        1: '10M',
        2: '100M',
        3: '1G',
        4: '5G',      # Estimated (between 2.5G and 10G)
        5: '2.5G',    # Confirmed from CRS326
        6: '10G',     # Alternate code (estimated)
        7: '10G',     # Confirmed from CRS305/CRS326
        8: '25G',     # Estimated
        9: '40G',     # Estimated
        10: '50G',    # Estimated
        11: '100G',   # Estimated
        12: '200G',   # Estimated
        13: '400G',   # Estimated
    }

    ports = []
    for i in range(len(port_names)):
        port_info = {
            'port_number': i + 1,
            'port_name': decode_hex_string(port_names[i]),
            'enabled': bool(enabled_mask & (1 << i)),
            'auto_negotiation': bool(auto_neg_mask & (1 << i)),
            'link_up': bool(link_up_mask & (1 << i)),
            'full_duplex': bool(full_duplex_mask & (1 << i)),
        }

        # Add speed
        if speed_array and i < len(speed_array):
            speed_code = speed_array[i]
            port_info['speed'] = speed_map.get(speed_code, f'{speed_code}')
        else:
            port_info['speed'] = 'unknown'

        # Add link status
        if link_status_array and i < len(link_status_array):
            # SwOS Lite format
            status_code = link_status_array[i]
            port_info['link_status'] = link_status_map.get(status_code, f'Unknown(0x{status_code:02x})')
        else:
            # SwOS format - derive from link_up
            port_info['link_status'] = 'link on' if port_info['link_up'] else 'no link'

        # Add uptime if available (SwOS Lite)
        if uptime_array and i < len(uptime_array):
            port_info['uptime'] = uptime_array[i]

        ports.append(port_info)

    return ports


def get_poe(url: str, username: str, password: str) -> List[dict]:
    """
    Fetch and parse PoE information

    Returns empty list if PoE is not supported.

    Args:
        url: Switch URL
        username: Username
        password: Password

    Returns:
        List of PoE port configs (empty if not supported):
        - port_number: Port number (1-based)
        - poe_mode: 'off', 'on', or 'auto'
        - poe_priority: Priority level (1-based)
        - voltage_level: 'auto', 'low', or 'high'
        - poe_status: Status string
        - lldp_enabled: LLDP PoE enabled (boolean)
        - poe_current_ma: Current in mA (if active)
        - poe_voltage_v: Voltage in V (if active)
        - poe_power_w: Power in W (if active)
        - lldp_power_w: LLDP requested power in W (if available)
    """
    adapter = _get_adapter(url, username, password)

    # Check if PoE is supported
    if not adapter.has_poe():
        return []

    try:
        data = adapter.get('poe')
        fm = adapter.field_map
    except:
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

    poe_modes = get_field(data, fm, 'poe_mode') or []
    poe_priorities = get_field(data, fm, 'poe_priority') or []
    voltage_levels = get_field(data, fm, 'poe_voltage') or []
    poe_status = get_field(data, fm, 'poe_status') or []
    poe_current = get_field(data, fm, 'poe_current') or []  # in mA
    poe_voltage = get_field(data, fm, 'poe_voltage_actual') or []  # in 0.1V
    poe_power = get_field(data, fm, 'poe_power') or []  # in 0.1W
    lldp_enabled_mask = get_field(data, fm, 'poe_lldp') or 0
    lldp_power = get_field(data, fm, 'poe_lldp_power') or []  # in 0.1W

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
        if i < len(poe_current) and poe_current[i] > 0:
            port_info['poe_current_ma'] = poe_current[i]
            port_info['poe_voltage_v'] = poe_voltage[i] / 10.0
            port_info['poe_power_w'] = poe_power[i] / 10.0

        # Add LLDP power if available
        if i < len(lldp_power) and lldp_power[i] > 0:
            port_info['lldp_power_w'] = lldp_power[i] / 10.0

        ports.append(port_info)

    return ports


def get_lag(url: str, username: str, password: str) -> List[dict]:
    """
    Fetch and parse LAG/LACP configuration

    Returns empty list if LAG/LACP is not supported.

    Args:
        url: Switch URL
        username: Username
        password: Password

    Returns:
        List of LAG configs (empty if not supported):
        - port_number: Port number (1-based)
        - lacp_mode: 'passive', 'active', or 'static'
        - lacp_group: LAG group number
        - lacp_trunk: Trunk ID
        - lacp_partner: Partner MAC address
    """
    adapter = _get_adapter(url, username, password)

    # Check if LAG is supported
    if not adapter.has_lacp():
        return []

    try:
        data = adapter.get('lag')
        fm = adapter.field_map
    except:
        return []

    # LACP mode mapping
    lacp_mode_map = {
        0x00: 'passive',
        0x01: 'active',
        0x02: 'static',
    }

    lacp_modes = get_field(data, fm, 'lag_mode') or []
    lacp_groups = get_field(data, fm, 'lag_group') or []
    lacp_trunk = get_field(data, fm, 'lag_trunk') or []
    lacp_partners = get_field(data, fm, 'lag_partner') or []

    ports = []
    for i in range(len(lacp_modes)):
        ports.append({
            'port_number': i + 1,
            'lacp_mode': lacp_mode_map.get(lacp_modes[i], f'Unknown(0x{lacp_modes[i]:02x})'),
            'lacp_group': lacp_groups[i] if i < len(lacp_groups) else 0,
            'lacp_trunk': lacp_trunk[i] if i < len(lacp_trunk) else 0,
            'lacp_partner': lacp_partners[i] if i < len(lacp_partners) else '',
        })

    return ports


def get_sfp_info(url: str, username: str, password: str) -> dict:
    """
    Fetch and parse SFP port information

    Returns empty dict if SFP info is not available.

    Args:
        url: Switch URL
        username: Username
        password: Password

    Returns:
        dict with SFP diagnostics data (empty if not supported)
    """
    adapter = _get_adapter(url, username, password)
    auth = adapter.auth

    try:
        response = requests.get(f"{adapter.url}/sfp.b", auth=auth, timeout=10, verify=False)
        response.raise_for_status()

        if not response.text or response.text.strip() == '':
            return {}

        data = parse_js_object(response.text)
        return data
    except:
        return {}


def get_snmp(url: str, username: str, password: str) -> dict:
    """
    Fetch and parse SNMP configuration

    Returns empty dict if SNMP is not supported.

    Args:
        url: Switch URL
        username: Username
        password: Password

    Returns:
        dict with SNMP config (empty if not supported):
        - enabled: SNMP enabled (boolean)
        - community: Community string
        - contact: Contact information
        - location: Device location
    """
    adapter = _get_adapter(url, username, password)

    # Check if SNMP is supported
    if not adapter.has_snmp():
        return {}

    try:
        data = adapter.get('snmp')
        fm = adapter.field_map

        return {
            'enabled': bool(get_field(data, fm, 'snmp_enabled') or 0),
            'community': decode_hex_string(get_field(data, fm, 'snmp_community') or ''),
            'contact': decode_hex_string(get_field(data, fm, 'snmp_contact') or ''),
            'location': decode_hex_string(get_field(data, fm, 'snmp_location') or ''),
        }
    except:
        return {}


# ============================================================================
# WRITE OPERATIONS - Configuration Updates
# ============================================================================

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

    Returns:
        Response text from POST request

    Raises:
        ValueError: If port number is invalid
        requests.HTTPError: If request fails
    """
    adapter = _get_adapter(url, username, password)
    fm = adapter.field_map

    # Get current port configuration
    current = get_links(url, username, password)
    port_idx = port_number - 1

    if port_idx >= len(current):
        raise ValueError(f"Invalid port number: {port_number}")

    # Get raw data for modification
    data = adapter.get('link')

    # Update the specific port
    if name is not None:
        names_field = fm.port_names
        data[names_field][port_idx] = encode_hex_string(name)

    if enabled is not None:
        enabled_field = fm.port_enabled
        enabled_mask = data[enabled_field]
        if enabled:
            enabled_mask |= (1 << port_idx)  # Set bit
        else:
            enabled_mask &= ~(1 << port_idx)  # Clear bit
        data[enabled_field] = enabled_mask

    if auto_negotiation is not None:
        auto_neg_field = fm.port_auto_neg
        auto_neg_mask = data[auto_neg_field]
        if auto_negotiation:
            auto_neg_mask |= (1 << port_idx)  # Set bit
        else:
            auto_neg_mask &= ~(1 << port_idx)  # Clear bit
        data[auto_neg_field] = auto_neg_mask

    # Build POST body - only send writable fields
    # Both platforms send: enabled, names, auto_neg, speed, duplex, flow_tx, flow_rx
    writable_data = {
        fm.port_enabled: data[fm.port_enabled],
        fm.port_names: data[fm.port_names],
        fm.port_auto_neg: data[fm.port_auto_neg],
        fm.port_speed: data[fm.port_speed],
        fm.port_duplex_config: data[fm.port_duplex_config],
        fm.port_flow_tx: data[fm.port_flow_tx],
        fm.port_flow_rx: data[fm.port_flow_rx]
    }
    post_data = build_post_data(writable_data)

    return adapter.post('link', post_data)


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

    Returns:
        Response text from POST request

    Raises:
        ValueError: If port number is invalid or doesn't support PoE
        requests.HTTPError: If request fails
    """
    adapter = _get_adapter(url, username, password)
    fm = adapter.field_map

    # Check if device supports PoE
    if not adapter.has_poe():
        raise ValueError("This device does not support PoE")

    # Get current PoE configuration
    current = get_poe(url, username, password)
    port_idx = port_number - 1

    if port_idx >= len(current):
        raise ValueError(f"Invalid port number: {port_number}")

    # Get raw data for modification
    data = adapter.get('poe')

    # Update the specific port
    if mode is not None:
        mode_map = {'off': 0x00, 'on': 0x01, 'auto': 0x02}
        data[fm.poe_mode][port_idx] = mode_map[mode]

    if priority is not None:
        data[fm.poe_priority][port_idx] = priority - 1  # Convert 1-based to 0-based

    if voltage_level is not None:
        voltage_map = {'auto': 0x00, 'low': 0x01, 'high': 0x02}
        data[fm.poe_voltage][port_idx] = voltage_map[voltage_level]

    if lldp_enabled is not None:
        lldp_mask = data.get(fm.poe_lldp, 0)
        # LLDP field is a bitmask for PoE ports
        # PoE-capable ports are typically the first N ports (e.g., 8 for CSS610-8P-2S+)
        MAX_POE_PORTS = len(data[fm.poe_mode])
        if port_idx >= MAX_POE_PORTS:
            raise ValueError(f"Port {port_number} does not support PoE LLDP (only ports 1-{MAX_POE_PORTS} support PoE/LLDP)")

        if lldp_enabled:
            lldp_mask |= (1 << port_idx)  # Set bit
        else:
            lldp_mask &= ~(1 << port_idx)  # Clear bit
        data[fm.poe_lldp] = lldp_mask

    # Build POST body - only send writable fields for PoE ports
    # Only include PoE-capable ports in arrays
    MAX_POE_PORTS = len(data[fm.poe_mode])
    writable_data = {
        fm.poe_mode: data[fm.poe_mode][:MAX_POE_PORTS],
        fm.poe_priority: data[fm.poe_priority][:MAX_POE_PORTS],
        fm.poe_voltage: data[fm.poe_voltage][:MAX_POE_PORTS],
        fm.poe_lldp: data[fm.poe_lldp]
    }
    post_data = build_post_data(writable_data)

    return adapter.post('poe', post_data)


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

    Returns:
        Response text from POST request

    Raises:
        ValueError: If port number is invalid
        requests.HTTPError: If request fails
    """
    adapter = _get_adapter(url, username, password)
    fm = adapter.field_map

    # Check if device supports LAG
    if not adapter.has_lacp():
        raise ValueError("This device does not support LAG/LACP")

    # Get current LAG configuration
    current = get_lag(url, username, password)
    port_idx = port_number - 1

    if port_idx >= len(current):
        raise ValueError(f"Invalid port number: {port_number}")

    # Get raw data for modification
    data = adapter.get('lag')

    # Update the specific port
    if mode is not None:
        mode_map = {'passive': 0x00, 'active': 0x01, 'static': 0x02}
        data[fm.lag_mode][port_idx] = mode_map[mode]

    if group is not None:
        data[fm.lag_group][port_idx] = group

    # Build POST body - only send writable fields
    writable_data = {
        fm.lag_mode: data[fm.lag_mode],
        fm.lag_group: data[fm.lag_group]
    }
    post_data = build_post_data(writable_data)

    return adapter.post('lag', post_data)


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

    Returns:
        Response text from POST request

    Raises:
        ValueError: If port number is invalid
        requests.HTTPError: If request fails
    """
    adapter = _get_adapter(url, username, password)
    fm = adapter.field_map

    # Get current VLAN configuration
    current = get_port_vlans(url, username, password)
    port_idx = port_number - 1

    if port_idx >= len(current):
        raise ValueError(f"Invalid port number: {port_number}")

    # Get raw data for modification
    data = adapter.get('vlan_port')

    # Update the specific port
    if vlan_mode is not None:
        mode_map = {'Disabled': 0, 'Optional': 1, 'Strict': 2}
        data[fm.vlan_port_mode][port_idx] = mode_map[vlan_mode]

    if vlan_receive is not None:
        receive_map = {'Any': 0, 'Only Tagged': 1, 'Only Untagged': 2}
        data[fm.vlan_port_receive][port_idx] = receive_map[vlan_receive]

    if default_vlan_id is not None:
        data[fm.vlan_port_default_id][port_idx] = default_vlan_id

    if force_vlan_id is not None:
        force_mask = data[fm.vlan_port_force_id]
        if force_vlan_id:
            force_mask |= (1 << port_idx)  # Set bit
        else:
            force_mask &= ~(1 << port_idx)  # Clear bit
        data[fm.vlan_port_force_id] = force_mask

    # Build POST body - only send writable fields
    writable_data = {
        fm.vlan_port_mode: data[fm.vlan_port_mode],
        fm.vlan_port_receive: data[fm.vlan_port_receive],
        fm.vlan_port_default_id: data[fm.vlan_port_default_id],
        fm.vlan_port_force_id: data[fm.vlan_port_force_id]
    }
    post_data = build_post_data(writable_data)

    return adapter.post('vlan_port', post_data)


def set_vlans(url, username, password, vlans):
    """
    Set VLAN table configuration

    Args:
        url: Switch URL
        username: Admin username
        password: Admin password
        vlans: List of VLAN dictionaries with:
            - vlan_id: VLAN ID (1-4094, required)
            - member_ports: List of port numbers (1-based, required)
            - igmp_snooping: IGMP snooping enabled (boolean, optional, defaults to False)

    Returns:
        Response text from POST request

    Raises:
        ValueError: If VLAN ID or port number is invalid
        requests.HTTPError: If request fails

    Example:
        vlans = [
            {'vlan_id': 1, 'member_ports': [1, 2, 3, 4]},
            {'vlan_id': 10, 'member_ports': [5, 6], 'igmp_snooping': True},
        ]
        set_vlans(url, username, password, vlans)
    """
    adapter = _get_adapter(url, username, password)
    fm = adapter.field_map
    port_count = adapter.get_port_count()

    # Build VLAN array
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
            if not (1 <= port_num <= port_count):
                raise ValueError(f"Port number must be between 1 and {port_count}, got {port_num}")
            port_mask |= (1 << (port_num - 1))

        vlan_array.append({
            fm.vlan_id: vlan_id,
            fm.vlan_members: port_mask,
            fm.vlan_igmp: 0x01 if igmp_snooping else 0x00,
        })

    # Build array POST data
    post_data = build_post_array(vlan_array)

    return adapter.post('vlan_table', post_data)


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

    Returns:
        Response text from POST request

    Raises:
        requests.HTTPError: If request fails
    """
    adapter = _get_adapter(url, username, password)
    fm = adapter.field_map

    # Check if device supports SNMP
    if not adapter.has_snmp():
        raise ValueError("This device does not support SNMP")

    # Get current SNMP configuration
    data = adapter.get('snmp')

    # Update fields
    if enabled is not None:
        data[fm.snmp_enabled] = 0x01 if enabled else 0x00

    if community is not None:
        data[fm.snmp_community] = encode_hex_string(community)

    if contact is not None:
        data[fm.snmp_contact] = encode_hex_string(contact)

    if location is not None:
        data[fm.snmp_location] = encode_hex_string(location)

    # Build POST body - send all fields (SNMP has only 4 fields, all writable)
    post_data = build_post_data(data)

    return adapter.post('snmp', post_data)


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

    Returns:
        Response text from POST request

    Raises:
        ValueError: If invalid IP, CIDR, port numbers, or VLAN ID
        requests.HTTPError: If request fails
    """
    adapter = _get_adapter(url, username, password)
    fm = adapter.field_map
    port_count = adapter.get_port_count()

    # Get current system configuration
    data = adapter.get('system')

    # Update identity
    if identity is not None:
        data[fm.system_identity] = encode_hex_string(identity)

    # Update address acquisition mode
    if address_acquisition is not None:
        addr_acq_map = {
            'DHCP with fallback': 0x00,
            'static': 0x01,
            'DHCP only': 0x02,
        }
        if address_acquisition not in addr_acq_map:
            raise ValueError(f"address_acquisition must be one of {list(addr_acq_map.keys())}, got '{address_acquisition}'")
        data[fm.system_address_acquisition] = addr_acq_map[address_acquisition]

    # Update static IP
    if static_ip is not None:
        data[fm.system_static_ip] = encode_ip_address_le(static_ip)

    # Update Allow From (IP/CIDR)
    if allow_from is not None:
        if allow_from == "":
            # Empty string means no restriction
            data[fm.system_allow_from_ip] = 0x00000000
            data[fm.system_allow_from_bits] = 0x00
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

            data[fm.system_allow_from_ip] = encode_ip_address_le(ip_part)
            data[fm.system_allow_from_bits] = bits

    # Update Allow From Ports (list to bitmask)
    if allow_from_ports is not None:
        port_mask = 0
        for port_num in allow_from_ports:
            if not (1 <= port_num <= port_count):
                raise ValueError(f"Port number must be between 1 and {port_count}, got {port_num}")
            port_mask |= (1 << (port_num - 1))
        data[fm.system_allow_from_ports] = port_mask

    # Update Allow From VLAN
    if allow_from_vlan is not None:
        if not (1 <= allow_from_vlan <= 4095):
            raise ValueError(f"allow_from_vlan must be between 1 and 4095, got {allow_from_vlan}")
        data[fm.system_allow_from_vlan] = allow_from_vlan

    # Build POST body - send all fields
    post_data = build_post_data(data)

    return adapter.post('system', post_data)
