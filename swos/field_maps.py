#!/usr/bin/env python3
"""
Field mapping definitions for SwOS/SwOS Lite platforms

Defines the structure for field ID mappings between logical field names
and platform-specific field identifiers.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class FieldMap:
    """
    Defines field IDs for a specific platform (SwOS or SwOS Lite)

    Field naming convention:
    - SwOS Lite: hex IDs like 'i01', 'i02', 'i0a'
    - SwOS: descriptive names like 'id', 'ver', 'en', 'nm'
    """

    # Platform metadata
    platform_name: str
    platform_type: str  # 'swos' or 'swos-lite'

    # Endpoint URLs (same for both platforms)
    endpoint_system: str = "sys.b"
    endpoint_link: str = "link.b"
    endpoint_poe: str = "poe.b"
    endpoint_lag: str = "lacp.b"
    endpoint_vlan_port: str = "fwd.b"
    endpoint_vlan_table: str = "vlan.b"
    endpoint_snmp: str = "snmp.b"

    # System fields (sys.b)
    system_uptime: str = ""
    system_current_ip: str = ""
    system_mac: str = ""
    system_serial: str = ""
    system_identity: str = ""
    system_version: str = ""
    system_model: str = ""
    system_build_date: str = ""
    system_static_ip: str = ""
    system_address_acquisition: str = ""
    system_allow_from_ip: str = ""
    system_allow_from_bits: str = ""
    system_allow_from_ports: str = ""
    system_allow_from_vlan: str = ""
    system_temperature: Optional[str] = None  # SwOS only
    system_fan1: Optional[str] = None  # SwOS only
    system_fan2: Optional[str] = None  # SwOS only
    system_poe_available: Optional[str] = None  # SwOS only
    system_management: Optional[str] = None  # SwOS only

    # Port/Link fields (link.b)
    port_enabled: str = ""
    port_names: str = ""
    port_auto_neg: str = ""
    port_duplex_config: str = ""
    port_duplex_status: str = ""
    port_link_status: str = ""  # Different formats between platforms
    port_link_up: str = ""
    port_speed: str = ""
    port_speed_config: Optional[str] = None  # SwOS only
    port_flow_tx: str = ""
    port_flow_rx: str = ""
    port_uptime: Optional[str] = None  # SwOS Lite only
    port_count: Optional[str] = None  # SwOS only (explicit field)
    port_sfp_count: Optional[str] = None  # SwOS only
    port_sfp_offset: Optional[str] = None  # SwOS only

    # PoE fields (poe.b) - if hardware supports
    poe_mode: str = ""
    poe_priority: str = ""
    poe_voltage: str = ""
    poe_status: str = ""
    poe_current: str = ""
    poe_voltage_actual: str = ""
    poe_power: str = ""
    poe_lldp: str = ""
    poe_lldp_power: str = ""

    # LAG fields (lacp.b)
    lag_mode: str = ""
    lag_trunk: str = ""  # Different meaning between platforms
    lag_group: str = ""
    lag_partner: str = ""

    # VLAN table fields (vlan.b) - array of objects
    vlan_id: str = ""
    vlan_members: str = ""
    vlan_igmp: str = ""
    vlan_name: Optional[str] = None  # SwOS only
    vlan_isolation: Optional[str] = None  # SwOS only
    vlan_learning: Optional[str] = None  # SwOS only
    vlan_mirror: Optional[str] = None  # SwOS only

    # VLAN per-port fields (fwd.b)
    vlan_port_mode: str = ""
    vlan_port_receive: str = ""
    vlan_port_default_id: str = ""
    vlan_port_force_id: str = ""
    vlan_port_forwarding: Optional[str] = None  # SwOS only (fp1, fp2, etc.)
    vlan_port_lock: Optional[str] = None  # SwOS only
    vlan_port_ingress_mirror: Optional[str] = None  # SwOS only
    vlan_port_egress_mirror: Optional[str] = None  # SwOS only

    # SNMP fields (snmp.b)
    snmp_enabled: str = ""
    snmp_community: str = ""
    snmp_contact: str = ""
    snmp_location: str = ""


def get_field(data: dict, field_map: FieldMap, field_name: str) -> any:
    """
    Get a field value from data using the field map

    Args:
        data: Parsed response data (dict)
        field_map: FieldMap for the platform
        field_name: Logical field name (e.g., 'system_identity')

    Returns:
        Field value, or None if not found

    Example:
        >>> get_field(data, css_map, 'system_identity')
        # Returns data['i05'] for SwOS Lite
        # Returns data['id'] for SwOS
    """
    field_id = getattr(field_map, field_name, None)
    if field_id:
        return data.get(field_id)
    return None


def set_field(data: dict, field_map: FieldMap, field_name: str, value: any) -> None:
    """
    Set a field value in data using the field map

    Args:
        data: Data dict to modify
        field_map: FieldMap for the platform
        field_name: Logical field name (e.g., 'system_identity')
        value: Value to set

    Example:
        >>> set_field(data, css_map, 'system_identity', '5357382d4f7074696373')
        # Sets data['i05'] for SwOS Lite
        # Sets data['id'] for SwOS
    """
    field_id = getattr(field_map, field_name, None)
    if field_id:
        data[field_id] = value


def has_field(field_map: FieldMap, field_name: str) -> bool:
    """
    Check if a field is supported by the platform

    Args:
        field_map: FieldMap for the platform
        field_name: Logical field name

    Returns:
        True if the field is defined (not None or empty string)
    """
    field_id = getattr(field_map, field_name, None)
    return bool(field_id)
