#!/usr/bin/env python3
"""
Field mappings for MikroTik SwOS (CRS/RB series switches)

Tested with:
- CRS305-1G-4S+ (SwOS 2.17)
- CRS310-8G+2S+ (SwOS 2.17)
"""

from .field_maps import FieldMap


SWOS_FIELD_MAP = FieldMap(
    platform_name="SwOS",
    platform_type="swos",

    # Endpoints (same for both platforms)
    endpoint_system="sys.b",
    endpoint_link="link.b",
    endpoint_poe="poe.b",
    endpoint_lag="lacp.b",
    endpoint_vlan_port="fwd.b",
    endpoint_vlan_table="vlan.b",
    endpoint_snmp="snmp.b",

    # System fields (sys.b)
    system_uptime="upt",
    system_current_ip="cip",
    system_mac="mac",
    system_serial="sid",
    system_identity="id",
    system_version="ver",
    system_model="brd",
    system_build_date="bld",
    system_static_ip="ip",
    system_address_acquisition="iptp",
    system_allow_from_ip="alla",
    system_allow_from_bits="allm",
    system_allow_from_ports="allp",
    system_allow_from_vlan="avln",
    # SwOS-specific fields
    system_temperature="temp",
    system_fan1="fan1",
    system_fan2="fan2",
    system_poe_available="poe",
    system_management="mgmt",

    # Port/Link fields (link.b)
    port_enabled="en",
    port_names="nm",
    port_auto_neg="an",
    port_duplex_config="dpxc",
    port_duplex_status="dpx",
    port_link_status=None,  # SwOS uses 'lnk' bitmask instead of status array
    port_link_up="lnk",
    port_speed="spd",
    port_speed_config="spdc",
    port_flow_tx="fctc",
    port_flow_rx="fctr",
    port_uptime=None,  # SwOS Lite only
    port_count="prt",  # Explicit field in SwOS
    port_sfp_count="sfp",
    port_sfp_offset="sfpo",

    # PoE fields (poe.b)
    # Note: These are educated guesses based on SwOS Lite mappings
    # Need to verify with a PoE-capable SwOS device (e.g., CRS328-24P-4S+)
    # For now, using likely field names based on pattern
    poe_mode="mode",  # Likely
    poe_priority="prio",  # Likely
    poe_voltage="volt",  # Likely
    poe_status="stat",  # Likely
    poe_current="cur",  # Likely
    poe_voltage_actual="volr",  # Likely
    poe_power="pwr",  # Likely
    poe_lldp="lldp",  # Likely
    poe_lldp_power="lldpp",  # Likely

    # LAG fields (lacp.b)
    lag_mode="mode",
    lag_trunk="sgrp",  # SwOS: sgrp (selected group), SwOS Lite: i02 (trunk)
    lag_group="grp",
    lag_partner="mac",

    # VLAN table fields (vlan.b)
    vlan_id="vid",
    vlan_members="mbr",
    vlan_igmp="igmp",
    # SwOS-specific VLAN fields
    vlan_name="nm",
    vlan_isolation="piso",
    vlan_learning="lrn",
    vlan_mirror="mrr",

    # VLAN per-port fields (fwd.b)
    vlan_port_mode="vlan",
    vlan_port_receive="vlni",
    vlan_port_default_id="dvid",
    vlan_port_force_id="fvid",
    # SwOS-specific forwarding fields
    vlan_port_forwarding="fp",  # Note: fp1, fp2, etc. per port
    vlan_port_lock="lck",
    vlan_port_ingress_mirror="imr",
    vlan_port_egress_mirror="omr",

    # SNMP fields (snmp.b)
    snmp_enabled="en",
    snmp_community="com",
    snmp_contact="ci",
    snmp_location="loc",
)
