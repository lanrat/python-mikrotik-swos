#!/usr/bin/env python3
"""
Field mappings for MikroTik SwOS Lite (CSS series switches)

Tested with:
- CSS610-8G-2S+ (SwOS Lite 2.20)
- CSS610-8P-2S+ (SwOS Lite 2.20)
"""

from .field_maps import FieldMap


CSS_FIELD_MAP = FieldMap(
    platform_name="SwOS Lite",
    platform_type="swos-lite",

    # Endpoints (same for both platforms)
    endpoint_system="sys.b",
    endpoint_link="link.b",
    endpoint_poe="poe.b",
    endpoint_lag="lacp.b",
    endpoint_vlan_port="fwd.b",
    endpoint_vlan_table="vlan.b",
    endpoint_snmp="snmp.b",

    # System fields (sys.b)
    system_uptime="i01",
    system_current_ip="i02",
    system_mac="i03",
    system_serial="i04",
    system_identity="i05",
    system_version="i06",
    system_model="i07",
    system_build_date="i0b",
    system_static_ip="i09",
    system_address_acquisition="i0a",
    system_allow_from_ip="i19",
    system_allow_from_bits="i1a",
    system_allow_from_ports="i12",
    system_allow_from_vlan="i1b",
    # SwOS-only fields are None for SwOS Lite
    system_temperature=None,
    system_fan1=None,
    system_fan2=None,
    system_poe_available=None,
    system_management=None,

    # Port/Link fields (link.b)
    port_enabled="i01",
    port_names="i0a",
    port_auto_neg="i02",
    port_duplex_config="i03",
    port_duplex_status="i07",
    port_link_status="i08",  # Array of status codes
    port_link_up="i06",
    port_speed="i05",
    port_speed_config=None,  # SwOS only
    port_flow_tx="i16",
    port_flow_rx="i12",
    port_uptime="i09",
    port_count=None,  # Implicit from array length
    port_sfp_count=None,  # SwOS only
    port_sfp_offset=None,  # SwOS only

    # PoE fields (poe.b)
    poe_mode="i01",
    poe_priority="i02",
    poe_voltage="i03",
    poe_status="i04",
    poe_current="i05",
    poe_voltage_actual="i06",
    poe_power="i07",
    poe_lldp="i0a",
    poe_lldp_power="i0b",

    # LAG fields (lacp.b)
    lag_mode="i01",
    lag_trunk="i02",  # SwOS Lite: trunk, SwOS: sgrp
    lag_group="i03",
    lag_partner="i04",

    # VLAN table fields (vlan.b)
    vlan_id="i01",
    vlan_members="i02",
    vlan_igmp="i03",
    vlan_name=None,  # SwOS only
    vlan_isolation=None,  # SwOS only
    vlan_learning=None,  # SwOS only
    vlan_mirror=None,  # SwOS only

    # VLAN per-port fields (fwd.b)
    vlan_port_mode="i15",
    vlan_port_receive="i17",
    vlan_port_default_id="i18",
    vlan_port_force_id="i19",
    vlan_port_forwarding=None,  # SwOS only
    vlan_port_lock=None,  # SwOS only
    vlan_port_ingress_mirror=None,  # SwOS only
    vlan_port_egress_mirror=None,  # SwOS only

    # SNMP fields (snmp.b)
    snmp_enabled="i01",
    snmp_community="i02",
    snmp_contact="i03",
    snmp_location="i04",
)
