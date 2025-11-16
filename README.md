# SwOS API and Tools

[![PyPI version](https://badge.fury.io/py/mikrotik-swos.svg)](https://pypi.org/project/mikrotik-swos/)
[![Python versions](https://img.shields.io/pypi/pyversions/mikrotik-swos.svg)](https://pypi.org/project/mikrotik-swos/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Python library and tools for managing MikroTik SwOS (SwitchOS) and SwOS Lite (SwitchOS Lite) switches.

## Components

- **swos package**: Python library for reading/writing switch configuration
- **swos-config**: CLI tool for displaying configuration
- **swos-export**: CLI tool for exporting configurations to Ansible YAML format
- **Ansible module**: Full-featured Ansible integration for declarative, idempotent switch configuration management
  - Supports check mode (dry-run)
  - Auto-detects platform (SwOS vs SwOS Lite)
  - Manages ports, PoE, VLANs, LAG/LACP, SNMP
  - See [ANSIBLE.md](ANSIBLE.md) for complete documentation

## Capabilities

**Read:** System info, ports, PoE, LAG/LACP, per-port VLANs, VLAN table, host table, SFP info, SNMP
**Write:** System settings, port config, PoE settings, LAG/LACP, per-port VLANs, VLAN table, SNMP
**Note:** All configuration changes are immediately applied and persisted by the switch.

## Requirements

- Python 3.6+
- requests>=2.25.0

## Installation

```bash
pip install mikrotik-swos
```

Or for development:

```bash
pip install -r requirements.txt
```

## Confirmed Compatibility

- SwOS 2.17
- SwOS 2.18

- SwOS Lite 2.17
- SwOS Lite 2.18
- SwOS Lite 2.19
- SwOS Lite 2.20

## Tested Hardware

- CRS305-1G-4S+
- CRS309-1G-8S+
- CRS310-8G+2S+
- CRS326-24S+2Q

- CSS610-8G-2S+
- CSS610-8P-2S+

**Note:** Gracefully handles switches without PoE, LAG/LACP, or SFP capabilities.

## Quick Start

### CLI Tools

**swos-config** - Display switch configuration:

```bash
# Display configuration
swos-config 192.168.88.1 admin ""

# Save to file
swos-config 192.168.88.1 admin "" > backup.txt
```

**swos-export** - Export to Ansible YAML format:

```bash
# Export all switches from inventory
swos-export -i inventory.yml -o configs/

# Export single switch
swos-export --host 192.168.1.1 --username admin --password "" -o switch.yml
```

### Python API

```python
from swos import get_system_info, set_port_config

url = "http://192.168.88.1"
system = get_system_info(url, "admin", "")
print(f"{system['device_name']} - {system['model']}")

set_port_config(url, "admin", "", port_number=1, name="Uplink")
```

See module docstrings for complete API documentation.

### Ansible - Infrastructure as Code

**Perfect for managing multiple switches declaratively!**

**Quick Setup:**

```bash
# Install package
pip install mikrotik-swos

# Copy module to your playbook
mkdir -p library
cp ansible/swos.py library/
```

**Example Playbook:**

```yaml
- name: Configure Switch
  hosts: switches
  tasks:
    - name: Apply configuration
      swos:
        host: "{{ ansible_host }}"
        username: admin
        password: ""
        config:
          system:
            identity: "Office-Switch-01"
          ports:
            - port: 1
              name: "Uplink"
              enabled: true
            - port: 2
              name: "Server"
              enabled: true
          vlans:
            - vlan_id: 10
              members: [2, 3, 4]
```

**Features:**

- Idempotent - only applies changes when needed
- Check mode - preview changes with `--check`
- Auto-detection - works with both SwOS and SwOS Lite
- Complete validation - catches configuration errors before applying

**[Full Ansible Documentation](ANSIBLE.md)** - Complete guide with advanced examples

## API Functions

**Read:** `get_system_info()`, `get_links()`, `get_poe()`, `get_lag()`, `get_port_vlans()`, `get_vlans()`, `get_hosts()`, `get_sfp_info()`, `get_snmp()`

**Write:** `set_system()`, `set_port_config()`, `set_poe_config()`, `set_lag_config()`, `set_port_vlan()`, `set_vlans()`, `set_snmp()`

All functions take `(url, username, password, ...)` parameters.
Read functions return lists of dictionaries with configuration data.
Write functions take port_number and optional setting parameters (except `set_system()`, `set_snmp()`, and `set_vlans()` which set global config).

See docstrings in the swos module for detailed parameters and return values.

## Security

- SwOS Lite uses HTTP with Digest Authentication (no HTTPS)
- Use on trusted networks only
- Use Ansible Vault for password storage

## Development

### Publishing a New Release

1. Create and push a git tag:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

2. GitHub Actions automatically builds and publishes to PyPI

## Credits

Certain components of this codebase were created with the assistance of AI.
