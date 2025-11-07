# SwOS Lite API and Tools

Python library and tools for managing MikroTik SwOS Lite switches (version 2.20+).

## Components

- **swos_lite package**: Python library for reading/writing switch configuration
- **swos-lite-config**: CLI tool for displaying configuration
- **Ansible module**: Declarative configuration management (see [ANSIBLE.md](ANSIBLE.md))

## Capabilities

**Read:** System info, ports, PoE, LAG/LACP, VLANs, host table, SFP info, SNMP
**Write:** Port config, PoE settings, LAG/LACP, per-port VLANs, SNMP
**Note:** All configuration changes are immediately applied and persisted by the switch.

## Requirements

- Python 3.6+
- requests>=2.25.0

## Installation

```bash
pip install swos-lite
```

Or for development:
```bash
pip install -r requirements.txt
```

## Compatibility

- SwOS Lite 2.18
- SwOS Lite 2.20

## Tested Hardware

- CSS610-8G-2S+
- CSS610-8P-2S+

**Note:** Gracefully handles switches without PoE, LAG/LACP, or SFP capabilities.

## Quick Start

### CLI Tool

```bash
# Display configuration
swos-lite-config 192.168.1.7 admin ""

# Save to file
swos-lite-config 192.168.1.7 admin "" > backup.txt
```

### Python API

```python
from swos_lite import get_system_info, set_port_config

url = "http://192.168.1.7"
system = get_system_info(url, "admin", "")
print(f"{system['device_name']} - {system['model']}")

set_port_config(url, "admin", "", port_number=1, name="Uplink")
```

See module docstrings for complete API documentation.

### Ansible

**Setup:**

1. Install the Python package:
   ```bash
   pip install swos-lite
   ```

2. Copy the module to your playbook's library directory:
   ```bash
   mkdir -p library
   cp ansible/swos_lite.py library/
   ```

**Usage:**

```bash
ansible-playbook apply_config.yml         # Apply configuration
ansible-playbook apply_config.yml --check # Preview changes
```

See [ANSIBLE.md](ANSIBLE.md) for complete documentation and examples.

## API Functions

**Read:** `get_system_info()`, `get_links()`, `get_poe()`, `get_lag()`, `get_port_vlans()`, `get_vlans()`, `get_hosts()`, `get_sfp_info()`, `get_snmp()`

**Write:** `set_port_config()`, `set_poe_config()`, `set_lag_config()`, `set_port_vlan()`, `set_snmp()`

All functions take `(url, username, password, ...)` parameters.
Read functions return lists of dictionaries with configuration data.
Write functions take port_number and optional setting parameters (except `set_snmp()` which sets global config).

See docstrings in the swos_lite module for detailed parameters and return values.

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
