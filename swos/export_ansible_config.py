#!/usr/bin/env python3
"""
Export switch configurations to Ansible-compatible YAML files.

This tool reads the current configuration from MikroTik SwOS/SwOS Lite switches
and exports them to YAML files compatible with the swos Ansible module.

Usage:
    swos-export -i inventory.yml -o output_dir/
    swos-export --host 192.168.1.1 --username admin --password "" -o switch.yml
"""

import argparse
import sys
import yaml
from pathlib import Path

from swos import (
    get_system_info,
    get_links,
    get_poe,
    get_lag,
    get_port_vlans,
    get_vlans,
    get_snmp
)


def export_switch_config(host, username, password):
    """
    Export configuration from a single switch.

    Args:
        host: Switch IP address or hostname
        username: Username for authentication
        password: Password for authentication

    Returns:
        dict: Configuration data compatible with Ansible module, or None on error
    """
    url = f"http://{host}"
    config = {}

    try:
        # Get system information
        system_info = get_system_info(url, username, password)
        if system_info:
            config['system'] = {
                'identity': system_info.get('identity'),
                'static_ip': system_info.get('static_ip'),
                'address_acquisition': system_info.get('address_acquisition'),
            }
            # Remove None values
            config['system'] = {k: v for k, v in config['system'].items() if v is not None}

        # Get port configuration
        links = get_links(url, username, password)
        if links:
            ports = []
            for link in links:
                port_config = {
                    'port': link['port_number'],
                    'name': link.get('port_name'),
                    'enabled': link.get('enabled'),
                    'auto_negotiation': link.get('auto_negotiation'),
                }
                # Remove None values and empty names
                port_config = {k: v for k, v in port_config.items() if v is not None and v != ''}
                ports.append(port_config)
            config['ports'] = ports

        # Get PoE configuration (if available)
        try:
            poe = get_poe(url, username, password)
            if poe:
                poe_configs = []
                for poe_port in poe:
                    poe_config = {
                        'port': poe_port['port_number'],
                        'mode': poe_port.get('poe_mode'),
                        'priority': poe_port.get('poe_priority'),
                        'voltage_level': poe_port.get('voltage_level'),
                        'lldp_enabled': poe_port.get('lldp_enabled'),
                    }
                    # Remove None values and only include if mode is not 'off'
                    poe_config = {k: v for k, v in poe_config.items() if v is not None}
                    if poe_config.get('mode') and poe_config.get('mode') != 'off':
                        poe_configs.append(poe_config)
                if poe_configs:
                    config['poe'] = poe_configs
        except Exception:
            pass  # PoE may not be available

        # Get LAG/LACP configuration (if available)
        try:
            lag = get_lag(url, username, password)
            if lag:
                lag_configs = []
                for lag_port in lag:
                    lag_config = {
                        'port': lag_port['port_number'],
                        'mode': lag_port.get('lacp_mode'),
                        'group': lag_port.get('lacp_group'),
                    }
                    # Remove None values and only include non-default configs
                    lag_config = {k: v for k, v in lag_config.items() if v is not None}
                    if (lag_config.get('mode') and lag_config.get('mode') != 'passive') or \
                       (lag_config.get('group') and lag_config.get('group') != 0):
                        lag_configs.append(lag_config)
                if lag_configs:
                    config['lag'] = lag_configs
        except Exception:
            pass  # LAG may not be available

        # Get VLAN table
        vlans = get_vlans(url, username, password)
        if vlans:
            vlan_configs = []
            for vlan in vlans:
                vlan_config = {
                    'vlan_id': vlan['vlan_id'],
                    'member_ports': vlan.get('member_ports', []),
                }
                if vlan.get('igmp_snooping') is not None:
                    vlan_config['igmp_snooping'] = vlan['igmp_snooping']
                # Only include VLANs that have members
                if vlan_config.get('member_ports'):
                    vlan_configs.append(vlan_config)
            if vlan_configs:
                config['vlans'] = vlan_configs

        # Get per-port VLAN configuration
        port_vlans = get_port_vlans(url, username, password)
        if port_vlans:
            port_vlan_configs = []
            for port_vlan in port_vlans:
                port_vlan_config = {
                    'port': port_vlan['port_number'],
                    'vlan_mode': port_vlan.get('vlan_mode'),
                    'vlan_receive': port_vlan.get('vlan_receive'),
                    'default_vlan_id': port_vlan.get('default_vlan_id'),
                }
                # Remove None values and only include non-default configs
                port_vlan_config = {k: v for k, v in port_vlan_config.items() if v is not None}
                if port_vlan_config.get('vlan_mode') != 'Disabled' or \
                   port_vlan_config.get('vlan_receive') != 'Any' or \
                   port_vlan_config.get('default_vlan_id', 1) != 1:
                    port_vlan_configs.append(port_vlan_config)
            if port_vlan_configs:
                config['port_vlans'] = port_vlan_configs

        # Get SNMP configuration
        snmp = get_snmp(url, username, password)
        if snmp:
            snmp_config = {
                'enabled': snmp.get('enabled'),
                'community': snmp.get('community'),
                'contact': snmp.get('contact'),
                'location': snmp.get('location'),
            }
            # Remove None values
            snmp_config = {k: v for k, v in snmp_config.items() if v is not None}
            if snmp_config:
                config['snmp'] = snmp_config

        return config

    except Exception as e:
        print(f"Error reading configuration from {host}: {e}", file=sys.stderr)
        return None


def export_from_inventory(inventory_file, output_dir):
    """
    Export configurations for all switches in an Ansible inventory file.

    Args:
        inventory_file: Path to Ansible inventory YAML file
        output_dir: Directory to save configuration files

    Returns:
        tuple: (success_count, fail_count)
    """
    # Load inventory
    with open(inventory_file) as f:
        inventory = yaml.safe_load(f)

    switches = inventory.get('switches', {}).get('hosts', {})
    if not switches:
        print("No switches found in inventory", file=sys.stderr)
        return 0, 0

    print(f"Found {len(switches)} switches in inventory\n")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    success_count = 0
    fail_count = 0

    for hostname, host_vars in switches.items():
        host = host_vars['ansible_host']
        username = host_vars.get('switch_username', 'admin')
        password = host_vars.get('switch_password', '')

        print(f"Reading configuration from {host} ({hostname})...")

        config = export_switch_config(host, username, password)

        if config:
            output_file = output_path / f'{hostname}.yml'
            with open(output_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)

            identity = config.get('system', {}).get('identity', 'Unknown')
            port_count = len(config.get('ports', []))
            print(f"  ✓ Configuration saved to {output_file}")
            print(f"    Identity: {identity}")
            print(f"    Ports: {port_count}")
            success_count += 1
        else:
            fail_count += 1

        print()

    return success_count, fail_count


def main():
    """Main entry point for CLI tool."""
    parser = argparse.ArgumentParser(
        description='Export MikroTik SwOS/SwOS Lite switch configurations to Ansible YAML format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Export all switches from inventory
  swos-export -i inventory.yml -o configs/

  # Export single switch
  swos-export --host 192.168.1.1 --username admin --password "" -o switch.yml

  # Export with custom credentials
  swos-export -i inventory.yml -o backups/ --username admin --password mypass
        """
    )

    # Inventory mode
    parser.add_argument('-i', '--inventory', metavar='FILE',
                        help='Ansible inventory file (YAML format)')
    parser.add_argument('-o', '--output', required=True, metavar='PATH',
                        help='Output directory (inventory mode) or file (single host mode)')

    # Single host mode
    parser.add_argument('--host', metavar='IP',
                        help='Single switch IP address or hostname')
    parser.add_argument('--username', metavar='USER', default='admin',
                        help='Username for authentication (default: admin)')
    parser.add_argument('--password', metavar='PASS', default='',
                        help='Password for authentication (default: empty)')

    args = parser.parse_args()

    # Validate arguments
    if args.inventory and args.host:
        parser.error("Cannot use both --inventory and --host")
    if not args.inventory and not args.host:
        parser.error("Must specify either --inventory or --host")

    try:
        if args.inventory:
            # Inventory mode
            success, fail = export_from_inventory(args.inventory, args.output)
            print(f"Export complete: {success} successful, {fail} failed")
            sys.exit(0 if fail == 0 else 1)
        else:
            # Single host mode
            print(f"Reading configuration from {args.host}...")
            config = export_switch_config(args.host, args.username, args.password)

            if config:
                output_file = Path(args.output)
                output_file.parent.mkdir(parents=True, exist_ok=True)

                with open(output_file, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False, sort_keys=False)

                identity = config.get('system', {}).get('identity', 'Unknown')
                port_count = len(config.get('ports', []))
                print(f"✓ Configuration saved to {output_file}")
                print(f"  Identity: {identity}")
                print(f"  Ports: {port_count}")
                sys.exit(0)
            else:
                sys.exit(1)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
