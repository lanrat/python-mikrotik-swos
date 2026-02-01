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
    vlan_mode: "Enabled"       # SwOS: Disabled/Optional/Enabled/Strict
                               # SwOS Lite: Disabled/Optional/Strict
    vlan_receive: "Only Untagged"
    default_vlan_id: 64
    force_vlan_id: false

vlans:
  - vlan_id: 1
    member_ports: [1, 2, 4, 5, 6, 7, 8, 9, 10]
  - vlan_id: 64
    member_ports: [3, 4, 5]
    igmp_snooping: true
    name: "Guest"           # SwOS only
  - vlan_id: 100
    member_ports: [9, 10]
    name: "Management"      # SwOS only
    isolation: true         # SwOS only
    learning: true          # SwOS only
    mirror: false           # SwOS only
```

**Note:** The `name`, `isolation`, `learning`, and `mirror` fields are only supported on SwOS (CRS series). They are ignored on SwOS Lite (CSS series).

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

**Update to latest version:**

```bash
# Pull latest changes from the repository
git pull origin main

# Re-copy the module file
cp ansible/swos.py library/
```

### Method 3: Python Package + Module Copy

Install the Python package globally or in a virtualenv, then copy just the Ansible module:

```bash
pip install mikrotik-swos
cp /path/to/site-packages/ansible/swos.py library/
```

**Update to latest version:**

```bash
# Upgrade the Python package
pip install --upgrade mikrotik-swos

# Re-copy the module file
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
| `backup` | No | `false` | Create backup before applying changes |
| `backup_options` | No | `{}` | Backup options: `filename` (custom name), `dir_path` (default: `./backups`) |

**Supported:** SNMP, port config, PoE, LAG/LACP, per-port VLANs, global VLAN table, backups
**Read-only:** Link status, speed/duplex, PoE power readings, host table, system info

**Backup Notes:**
- Backups are binary `.swb` files (MikroTik proprietary encrypted format)
- Backups are created BEFORE applying any configuration changes
- Backup is skipped in check mode (dry-run)
- If switch has default configuration, backup may fail (nothing to save)
- Backup path is returned in `backup_path` result variable

**Backup Filename Behavior:**
- **With custom filename** (`filename: "{{ inventory_hostname }}_config.swb"`):
  - Creates: `sw1_config.swb`, `sw2_config.swb`, etc.
  - Each switch gets a unique file based on inventory hostname
  - **Files are overwritten on each playbook run** (only keeps latest backup)
  - Useful when you only need the most recent backup before changes
- **Without custom filename** (omit `filename` parameter):
  - Creates: `192.168.88.1_20260131_143052.swb`, etc.
  - Each run creates a new timestamped file
  - **Files are never overwritten** (keeps full backup history)
  - Useful for maintaining historical backup records

## Playbook Example

### Basic Configuration

```yaml
- name: Configure Switch
  hosts: localhost
  tasks:
    - name: Apply configuration
      swos:
        host: "192.168.88.1"
        config: "{{ lookup('file', 'switch_config.yml') | from_yaml }}"
```

### With Automatic Backup

```yaml
- name: Configure Switch with Backup
  hosts: switches
  gather_facts: no
  tasks:
    - name: Create backups directory
      delegate_to: localhost
      file:
        path: "{{ playbook_dir }}/backups"
        state: directory
        mode: '0755'
      run_once: true

    - name: Apply configuration with backup
      swos:
        host: "{{ ansible_host }}"
        username: "{{ switch_username | default('admin') }}"
        password: "{{ switch_password | default('') }}"
        config: "{{ lookup('file', 'switch_config.yml') | from_yaml }}"
        backup: yes
        backup_options:
          filename: "{{ inventory_hostname }}_config.swb"
          dir_path: "{{ playbook_dir }}/backups"
      register: result

    - name: Display backup location
      debug:
        msg: "Backup saved to: {{ result.backup_path }}"
      when: result.backup_path is defined
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
