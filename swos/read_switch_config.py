#!/usr/bin/env python3
"""
SwitchOS Configuration Reader

This script reads and displays the complete configuration of a MikroTik SwOS/SwOS Lite
device in a human-readable format using the swos library.

Requirements:
    - swos library (included in this repository)
    - requests library (pip install requests)

Usage:
    python read_switch_config.py <switch_ip> <username> <password>

Example:
    python read_switch_config.py 192.168.88.1 admin ""
"""

import sys
import argparse
from swos import (
    get_system_info,
    get_links,
    get_poe,
    get_lag,
    get_vlans,
    get_port_vlans,
    get_hosts,
    decode_hex_string
)


def print_section_header(title):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


def print_subsection_header(title):
    """Print a formatted subsection header"""
    print(f"\n--- {title} ---")


def format_system_info(system_info):
    """Format and display system information"""
    print_section_header("SYSTEM INFORMATION")

    print(f"\n  Device Model:  {system_info.get('model', 'N/A')}")
    print(f"  Device Name:   {system_info.get('device_name', 'N/A')}")
    print(f"  Version:       {system_info.get('version', 'N/A')}")
    print(f"  Serial Number: {system_info.get('serial_number', 'N/A')}")
    print(f"  MAC Address:   {system_info.get('mac_address', 'N/A')}")
    print(f"  Uptime:        {system_info.get('uptime', 0)} seconds")


def format_link_info(ports):
    """Format and display port/link configuration information"""
    print_section_header("PORT/LINK CONFIGURATION")

    if not ports:
        print("No port information available")
        return

    # Header
    print(f"\n{'Port #':<8} {'Port Name':<20} {'Enabled':<10} {'Link Status':<15} {'Auto-Neg':<10} {'Duplex':<10}")
    print("-" * 80)

    # Port details
    for port in ports:
        port_num = port.get('port_number', 'N/A')
        port_name = port.get('port_name', 'N/A')
        enabled = 'Yes' if port.get('enabled') else 'No'
        link_status = port.get('link_status', 'N/A')
        auto_neg = 'Yes' if port.get('auto_negotiation') else 'No'
        duplex = 'Full' if port.get('full_duplex') else 'Half'

        print(f"{port_num:<8} {port_name:<20} {enabled:<10} {link_status:<15} {auto_neg:<10} {duplex:<10}")


def format_poe_info(ports):
    """Format and display PoE configuration information"""
    print_section_header("PoE CONFIGURATION")

    if not ports:
        print("No PoE information available")
        return

    # Header
    print(f"\n{'Port #':<8} {'Mode':<8} {'Priority':<10} {'Voltage':<10} {'Status':<20} {'Current':<12} {'Voltage':<10} {'Power':<10}")
    print("-" * 90)

    # Port details
    for port in ports:
        port_num = port.get('port_number', 'N/A')
        mode = port.get('poe_mode', 'N/A')
        priority = port.get('poe_priority', 'N/A')
        voltage_level = port.get('voltage_level', 'N/A')
        status = port.get('poe_status', 'N/A')

        current = f"{port.get('poe_current_ma', 0)}mA" if 'poe_current_ma' in port else '-'
        voltage = f"{port.get('poe_voltage_v', 0):.1f}V" if 'poe_voltage_v' in port else '-'
        power = f"{port.get('poe_power_w', 0):.1f}W" if 'poe_power_w' in port else '-'

        print(f"{port_num:<8} {mode:<8} {priority:<10} {voltage_level:<10} {status:<20} {current:<12} {voltage:<10} {power:<10}")


def format_lag_info(ports):
    """Format and display LAG/LACP configuration information"""
    print_section_header("LAG/LACP CONFIGURATION")

    if not ports:
        print("No LAG information available")
        return

    # Header
    print(f"\n{'Port #':<8} {'LACP Mode':<15} {'Group':<10} {'Trunk':<10} {'Partner':<30}")
    print("-" * 75)

    # Port details
    for port in ports:
        port_num = port.get('port_number', 'N/A')
        mode = port.get('lacp_mode', 'N/A')
        group = port.get('lacp_group', 'N/A')
        trunk = port.get('lacp_trunk', 'N/A')
        partner = port.get('lacp_partner', '-')

        print(f"{port_num:<8} {mode:<15} {group:<10} {trunk:<10} {partner:<30}")


def format_vlan_port_info(vlan_ports):
    """Format and display per-port VLAN configuration"""
    print_section_header("PER-PORT VLAN CONFIGURATION")

    if not vlan_ports:
        print("No VLAN port information available")
        return

    # Header
    print(f"\n{'Port #':<8} {'VLAN Mode':<15} {'Receive':<20} {'Default VLAN':<12}")
    print("-" * 60)

    # VLAN port details
    for vlan_port in vlan_ports:
        port_num = vlan_port.get('port_number', 'N/A')
        vlan_mode = vlan_port.get('vlan_mode', 'N/A')
        vlan_receive = vlan_port.get('vlan_receive', 'N/A')
        default_vlan = vlan_port.get('default_vlan_id', 'N/A')

        print(f"{port_num:<8} {vlan_mode:<15} {vlan_receive:<20} {default_vlan:<12}")


def format_vlan_config(vlan_config):
    """Format and display global VLAN configuration"""
    print_section_header("GLOBAL VLAN CONFIGURATION")

    if not vlan_config:
        print("No global VLAN configuration available")
        return

    for vlan in vlan_config:
        vlan_id = vlan.get('vlan_id', 'N/A')
        print_subsection_header(f"VLAN {vlan_id}")

        # Member ports (already decoded by get_vlans)
        members = vlan.get('member_ports', [])
        if members:
            print(f"  Member Ports: {', '.join(map(str, members))}")
        else:
            print(f"  Member Ports: None")


def format_hosts(hosts, port_names=None):
    """Format and display learned MAC addresses (host table)"""
    print_section_header("LEARNED MAC ADDRESSES (HOST TABLE)")

    if not hosts or len(hosts) == 0:
        print("No hosts learned")
        return

    # Header
    print(f"\n{'MAC Address':<20} {'Port #':<8} {'Port Name':<20}")
    print("-" * 50)

    # Host details
    for host in hosts:
        mac = host.get('mac_address', 'N/A')
        port_num = host.get('port_number', 'N/A')

        # Get port name from port_names dict if available
        if port_names and port_num in port_names:
            port_name = port_names[port_num]
        else:
            port_name = f"Port{port_num}"

        print(f"{mac:<20} {port_num:<8} {port_name:<20}")


def read_switch_config(switch_url, username, password):
    """
    Read complete switch configuration and display it in human-readable format

    Args:
        switch_url: URL of the switch (e.g., "http://192.168.88.1")
        username: Switch username
        password: Switch password
    """
    print(f"\nConnecting to switch at {switch_url}...")
    print(f"Username: {username}")

    try:
        # Retrieve system information
        print("\nRetrieving system information...")
        system_info = get_system_info(switch_url, username, password)
        format_system_info(system_info)

        # Retrieve link/port configuration
        print("\nRetrieving port configuration...")
        links = get_links(switch_url, username, password)
        format_link_info(links)

        # Build port name mapping for host table
        port_names = {port['port_number']: port['port_name'] for port in links}

        # Retrieve PoE configuration
        print("\nRetrieving PoE configuration...")
        poe = get_poe(switch_url, username, password)
        format_poe_info(poe)

        # Retrieve LAG configuration
        print("\nRetrieving LAG configuration...")
        lag = get_lag(switch_url, username, password)
        format_lag_info(lag)

        # Retrieve per-port VLAN configuration
        print("\nRetrieving VLAN port configuration...")
        vlan_ports = get_port_vlans(switch_url, username, password)
        format_vlan_port_info(vlan_ports)

        # Retrieve global VLAN configuration
        print("\nRetrieving global VLAN configuration...")
        vlan_config = get_vlans(switch_url, username, password)
        format_vlan_config(vlan_config)

        # Retrieve learned hosts
        print("\nRetrieving learned MAC addresses...")
        hosts = get_hosts(switch_url, username, password)
        format_hosts(hosts, port_names)

        # Summary
        print_section_header("CONFIGURATION SUMMARY")
        print(f"  Total Ports: {len(links) if links else 0}")
        print(f"  Total VLANs: {len(vlan_config) if vlan_config else 0}")
        print(f"  Learned Hosts: {len(hosts) if hosts else 0}")
        print("\n" + "=" * 80 + "\n")

    except Exception as e:
        print(f"\nError reading switch configuration: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Read and display MikroTik SwitchOS Lite configuration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s 192.168.88.1 admin password
  %(prog)s 192.168.88.1 admin ""
  %(prog)s --url http://192.168.88.1 --username admin --password pass
        '''
    )

    # Positional arguments (simple usage)
    parser.add_argument('switch_ip', nargs='?',
                        help='IP address of the switch (e.g., 192.168.88.1)')
    parser.add_argument('username', nargs='?', default='admin',
                        help='Username for switch authentication (default: admin)')
    parser.add_argument('password', nargs='?', default='',
                        help='Password for switch authentication (default: empty string)')

    # Named arguments (alternative usage)
    parser.add_argument('--url', dest='switch_url',
                        help='Full URL of the switch (e.g., http://192.168.88.1)')
    parser.add_argument('--username', dest='user',
                        help='Username for authentication')
    parser.add_argument('--password', dest='pwd',
                        help='Password for authentication')

    args = parser.parse_args()

    # Determine which arguments to use
    if args.switch_url:
        switch_url = args.switch_url
        username = args.user if args.user else 'admin'
        password = args.pwd if args.pwd else ''
    elif args.switch_ip:
        # Add http:// prefix if not present
        if not args.switch_ip.startswith('http'):
            switch_url = f"http://{args.switch_ip}"
        else:
            switch_url = args.switch_ip
        username = args.username
        password = args.password
    else:
        parser.print_help()
        sys.exit(1)

    read_switch_config(switch_url, username, password)


if __name__ == '__main__':
    main()
