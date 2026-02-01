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

## Simplified Port Configuration (Access/Trunk Model)

As an alternative to the detailed `port_vlans` and `vlans` sections, you can use the simplified `port_config` format with familiar access/trunk port terminology. The module automatically transforms this to the detailed format.

### Basic Example

```yaml
port_config:
  1:
    mode: trunk
    native_vlan: 1
    allowed_vlans: [1, 64, 539]
  2:
    mode: trunk
    native_vlan: 1
    allowed_vlans: [1, 64]
  3:
    mode: access
    vlan: 64
```

This automatically generates:
- **port_vlans**: Per-port VLAN settings (vlan_mode, vlan_receive, default_vlan_id, force_vlan_id)
- **vlans**: VLAN table with member_ports derived from port assignments

### Port Modes

| Mode | Description | Default vlan_mode |
|------|-------------|-------------------|
| `access` | Single untagged VLAN | Strict |
| `trunk` | Tagged VLANs with native VLAN | Optional |

### Overriding vlan_mode

By default, trunk ports use `Optional` (works on both SwOS and SwOS Lite) and access ports use `Strict`. You can override this per-port using the `vlan_mode` field:

```yaml
port_config:
  1:
    mode: trunk
    native_vlan: 1
    vlan_mode: Enabled  # Use 802.1Q Enabled mode (SwOS only)
    allowed_vlans: [1, 64, 539]
  3:
    mode: access
    vlan: 64
    # vlan_mode defaults to Strict (no override needed)
```

**Note:** `Enabled` mode is only supported on SwOS (CRS series). Using it on SwOS Lite (CSS series) will fail. Use `Optional` for mixed-platform environments.

### VLAN Groups

Reduce redundancy by defining named VLAN groups:

```yaml
vlan_groups:
  all_vlans: [1, 64, 539]
  servers: [1, 64]
  iot: [539]

port_config:
  1:
    mode: trunk
    native_vlan: 1
    vlan_group: all_vlans      # Reference a group
  2:
    mode: trunk
    native_vlan: 1
    vlan_group: servers
  3:
    mode: access
    vlan: 64
```

### Trunk Port Defaults

For trunk ports:
- **native_vlan**: Defaults to 1 if not specified
- **allowed_vlans/vlan_group**: If neither is specified, defaults to ALL VLANs referenced anywhere in the configuration

```yaml
port_config:
  1:
    mode: trunk    # native_vlan=1, allowed_vlans=all VLANs in config
```

### Native VLAN Behavior

**Important:** The native VLAN is always automatically included in the allowed VLANs for trunk ports, even if not explicitly listed in `allowed_vlans` or `vlan_group`. This is required for proper 802.1Q operation.

If the native VLAN is not in your explicit allowed list, a warning will be displayed:

```text
[WARNING]: Port 6: native_vlan 1 not in allowed VLANs, automatically added
(native VLAN is always allowed on trunk ports)
```

To remove a port from a VLAN entirely, you must also change the `native_vlan` to a different VLAN:

```yaml
port_config:
  6:
    mode: trunk
    native_vlan: 539       # Changed from 1
    vlan_group: iot_only   # Group that doesn't include VLAN 1
```

### Combining with Additional VLAN Settings

You can use `port_config` alongside a `vlans` section to add extra settings like IGMP snooping. The module merges them:

```yaml
port_config:
  1:
    mode: trunk
    native_vlan: 1
    allowed_vlans: [1, 64]
  3:
    mode: access
    vlan: 64

vlans:
  # These settings are merged with auto-generated VLAN entries
  - vlan_id: 64
    igmp_snooping: true
  - vlan_id: 100
    member_ports: [9, 10]    # Additional VLAN not in port_config
```

### Shared VLANs Across Switches

Use Ansible `group_vars` to share VLAN definitions across multiple switches. The shared variables are merged into the config at playbook execution time using the `combine()` filter.

**Directory structure:**

```text
ansible/
├── ansible.cfg
├── inventory.yml
├── group_vars/
│   └── switches.yml      # Shared VLAN definitions
├── switches/
│   ├── apply_all_configs.yml
│   └── switch_config.yml # Per-switch port assignments
```

**group_vars/switches.yml:**

```yaml
# Shared VLAN groups for all switches
shared_vlan_groups:
  all_vlans: [1, 64, 539]
  servers: [1, 64]

# Shared VLAN table settings
shared_vlans:
  - vlan_id: 1
    igmp_snooping: false
  - vlan_id: 64
    igmp_snooping: true
  - vlan_id: 539
    igmp_snooping: false
```

**switches/switch_config.yml** (pure YAML, no Jinja2):

```yaml
# Per-switch port assignments only
# vlan_groups and vlans are merged from group_vars in the playbook
port_config:
  1:
    mode: trunk
    native_vlan: 1
    vlan_group: all_vlans
  2:
    mode: trunk
    native_vlan: 1
    vlan_group: servers
  3:
    mode: access
    vlan: 64
```

**switches/apply_all_configs.yml:**

```yaml
---
- name: Apply Per-Switch Configurations
  hosts: switches
  gather_facts: no
  connection: local

  tasks:
    - name: Load switch-specific configuration
      set_fact:
        switch_config: >-
          {{ lookup('file', playbook_dir + '/' + config_file) | from_yaml |
             combine({'vlan_groups': shared_vlan_groups, 'vlans': shared_vlans}) }}

    - name: Apply switch configuration
      swos:
        host: "{{ ansible_host }}"
        username: "{{ switch_username | default('admin') }}"
        password: "{{ switch_password | default('') }}"
        config: "{{ switch_config }}"
```

**inventory.yml:**

```yaml
all:
  children:
    switches:
      hosts:
        sw1:
          ansible_host: 192.168.88.7
          switch_username: admin
          switch_password: "{{ switch_password }}"
          config_file: switch_config.yml
        sw2:
          ansible_host: 192.168.88.2
          config_file: sw2_config.yml
```

**Key points:**

- Switch config files are pure YAML (no Jinja2 expressions)
- The playbook uses `combine()` to merge shared variables from `group_vars`
- Each switch can reference a different `config_file` in the inventory
- Shared `vlan_groups` and `vlans` are available to all switches automatically

### Backward Compatibility

The detailed format (`port_vlans` and `vlans`) continues to work unchanged. You can use either format, but not both `port_config` and `port_vlans` in the same config (use one or the other for port VLAN settings).

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
