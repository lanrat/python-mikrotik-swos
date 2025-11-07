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
- **port_vlans**: VLAN mode, receive filter, default VLAN (writable)
- **vlans**: Global VLAN membership (planned)

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
| `config` | No | `{}` | Configuration with sections: snmp, ports, poe, lag, port_vlans |

**Supported:** SNMP, port config, PoE, LAG/LACP, per-port VLANs
**Read-only:** Link status, speed/duplex, PoE power readings, host table, system info
**Planned:** Global VLAN membership

## Playbook Example

```yaml
- name: Configure Switch
  hosts: localhost
  tasks:
    - name: Apply configuration
      swos_lite:
        host: "192.168.1.7"
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
