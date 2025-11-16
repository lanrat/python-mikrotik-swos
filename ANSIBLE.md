# Ansible Module for SwOS Lite

Declarative configuration management for MikroTik SwOS Lite switches (2.20+).

**Features:** Idempotent, check mode support, structured YAML configuration, detailed change reporting

## Configuration Format

Configuration file (`switch_config.yml`) organized by sections:

- **system**: System info (read-only, ignored by Ansible, for documentation only)
- **snmp**: SNMP enabled, community, contact, location (writable)
- **ports**: Port names, enabled state, auto-negotiation (writable)
- **poe**: PoE mode, priority, voltage level, LLDP enabled (writable)
- **lag**: LAG/LACP mode, group assignment (writable)
- **port_vlans**: Per-port VLAN mode, receive filter, default VLAN, force VLAN ID (writable)
- **vlans**: Global VLAN table - VLAN IDs, member ports, IGMP snooping (writable)

Example `switch_config.yml`:

```yaml
system:
  device_name: "MikroTik-SW1"
  model: "CSS610-8P-2S+"

snmp:
  enabled: true
  community: "public"
  contact: "admin@example.com"
  location: "Server Room"

ports:
  - port: 1
    name: "Uplink"
    enabled: true

poe:
  - port: 2
    mode: "auto"
    priority: 1

lag:
  - port: 9
    mode: "active"
    group: 1

port_vlans:
  - port: 3
    vlan_mode: "Enabled"
    vlan_receive: "Only Untagged"
    default_vlan_id: 64
    force_vlan_id: false

vlans:
  - vlan_id: 1
    member_ports: [1, 2, 4, 5, 6, 7, 8, 9, 10]
  - vlan_id: 64
    member_ports: [3, 4, 5]
    igmp_snooping: true
  - vlan_id: 100
    member_ports: [9, 10]
```

## Installation Methods

### Method 1: Git Submodule (Recommended for Infrastructure Repos)

Add this repository as a submodule to your Ansible configuration repository:

```bash
# In your ansible repository root
git submodule add https://github.com/lanrat/python-mikrotik-swos.git modules/swos

# Initialize and update the submodule
git submodule update --init --recursive

# Install the swos Python library from the submodule in editable mode
# This ensures the Ansible module can import the swos package
pip install -e modules/swos

# Commit the submodule addition
git add .gitmodules modules/swos
git commit -m "Add swos module as submodule"
```

**Configure ansible.cfg to use the submodule:**

```ini
[defaults]
library = ./modules/swos/ansible
```

**Clone your repository with submodules:**

```bash
# New clones
git clone --recursive https://github.com/yourname/your-ansible-repo.git
cd your-ansible-repo

# Install the swos library from the submodule
pip install -e modules/swos

# Existing clones
git submodule update --init --recursive
pip install -e modules/swos
```

**Update submodule to latest version:**

```bash
cd modules/swos
git pull origin main
cd ../..
git add modules/swos
git commit -m "Update swos module"
# No need to reinstall - editable mode automatically uses the updated code
```

**Benefits of this approach:**

- Single source of truth: Ansible module and Python library are from the same submodule
- No version mismatches between module and library
- Version controlled via git submodule
- Editable mode means updates to the submodule are immediately reflected
- Can pin to specific versions by checking out tags in the submodule

### Method 2: Copy Module Files

Copy the module to your playbook's library directory:

```bash
mkdir -p library
cp ansible/swos.py library/
```

### Method 3: Python Package + Module Copy

Install the Python package globally or in a virtualenv, then copy just the Ansible module:

```bash
pip install mikrotik-swos
cp /path/to/site-packages/ansible/swos.py library/
```

## Usage

### Setup

1. Create inventory file from example:

   ```bash
   cp inventory.example.yml inventory.yml
   ```

2. Edit `inventory.yml` with your switch details

### Run Playbook

```bash
# Apply configuration
ansible-playbook -i inventory.yml apply_config.yml

# Preview changes (dry run)
ansible-playbook -i inventory.yml apply_config.yml --check

# Apply to specific switch
ansible-playbook -i inventory.yml apply_config.yml --limit sw1

# With vault password
ansible-playbook -i inventory.yml apply_config.yml --ask-vault-pass
```

## Module Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `host` | Yes | - | Switch IP/hostname |
| `username` | No | `admin` | Username |
| `password` | No | `""` | Password |
| `config` | No | `{}` | Configuration with sections: snmp, ports, poe, lag, port_vlans, vlans |

**Supported:** SNMP, port config, PoE, LAG/LACP, per-port VLANs, global VLAN table
**Read-only:** Link status, speed/duplex, PoE power readings, host table, system info

## Playbook Example

```yaml
- name: Configure Switch
  hosts: localhost
  tasks:
    - name: Apply configuration
      swos:
        host: "192.168.88.1"
        config: "{{ lookup('file', 'switch_config.yml') | from_yaml }}"
```

## Password Security

Use Ansible Vault for passwords:

```bash
# Create vault file
ansible-vault create secrets.yml

# Add password
switch_password: "your_password"

# Run playbook
ansible-playbook apply_config.yml --ask-vault-pass
```

## License

See LICENSE file.
