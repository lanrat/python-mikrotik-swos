# MikroTik SwOS Lite HTTP API Reference

## Overview

MikroTik SwOS Lite uses a simple HTTP-based API with Digest Authentication. Configuration is stored in `.b` files that use JavaScript-like object notation with hex-encoded values.

## Authentication

All requests require HTTP Digest Authentication:

```bash
curl --digest -u admin:password "http://192.168.88.1/link.b"
```

## Data Format

### Response Format

Responses use JavaScript object notation with hex values:

```javascript
{i01:0x03ff,i0a:['506f727431','506f727432'],i02:0x03ff}
```

### Field Types

- **Scalars**: Single hex values (bitmasks or single values)
  - Example: `i01:0x03ff` (bitmask where each bit represents a port)
  - Example: `i19:0x04` (scalar value)
- **Arrays**: Lists of hex values (per-port settings)
  - Example: `i0a:['506f727431','506f727432']` (hex-encoded strings)
  - Example: `i01:[0x02,0x02,0x02]` (numeric values per port)

### Hex Encoding

- **Strings**: ASCII characters encoded as hex pairs
  - "Port1" → `'506f727431'`
  - Empty string → `''`
- **Numbers**: Prefixed with `0x`
  - 255 → `0x00ff` (in GET responses - padded)
  - 255 → `0xff` (in POST requests - even-length hex: 2, 4, 6, or 8 digits)

## API Endpoints

| Endpoint | Purpose | Fields |
|----------|---------|--------|
| `link.b` | Port configuration | Names, enabled, auto-negotiation, speed, duplex, flow control |
| `poe.b` | PoE configuration | Mode, priority, voltage, LLDP (ports 1-8 only) |
| `lacp.b` | LAG/LACP configuration | Mode, group |
| `fwd.b` | Forwarding/VLAN configuration | VLAN mode, VLAN receive, default VLAN ID, port mirroring, rate limiting |
| `snmp.b` | SNMP configuration | Enabled, community, contact, location |
| `vlan.b` | VLAN table | VLAN IDs, members, IGMP snooping |
| `sys.b` | System configuration | Identity, IP settings, management access, IGMP, MDP, RSTP |
| `rstp.b` | RSTP per-port | RSTP enabled, role, cost |
| `sfp.b` | SFP module info | Vendor, temperature, voltage (read-only) |

## Making Requests

### Reading Configuration (GET)

```bash
# Get port configuration
curl --digest -u admin:password "http://192.168.88.1/link.b"

# Get PoE status
curl --digest -u admin:password "http://192.168.88.1/poe.b"

# Get SNMP settings
curl --digest -u admin:password "http://192.168.88.1/snmp.b"
```

### Writing Configuration (POST)

#### Critical Requirements

1. Use `Content-Type: text/plain` (not `application/x-www-form-urlencoded`)
2. Use even-length hex for scalars: `0x04` not `0x4`, `0x03ff` not `0x3ff`
3. Use 2-digit hex for array elements: `0x02` not `0x0002`
4. Only send writable fields (exclude read-only fields)
5. For per-port settings, send all ports in the array

#### Example: Change Port Name

```bash
# 1. GET current config
curl --digest -u admin:password "http://192.168.88.1/link.b"
# Response: {i01:0x03ff,i0a:['506f727431','506f727432',...],i02:0x03ff,...}

# 2. Modify the desired field (i0a[0] = "NewName" = hex:'4e65774e616d65')
# 3. POST with ONLY writable fields
curl --digest -u admin:password \
  -H "Content-Type: text/plain" \
  -d "{i01:0x03ff,i0a:['4e65774e616d65','506f727432',...],i02:0x03ff,i05:[0x00,...],i03:0x03ff,i16:0x00,i12:0x00}" \
  "http://192.168.88.1/link.b"
```

#### Example: Enable PoE on Port 1

```bash
# 1. GET current config
curl --digest -u admin:password "http://192.168.88.1/poe.b"

# 2. Change i01[0] from 0x00 (off) to 0x02 (auto)
# 3. POST only writable fields for first 8 ports
curl --digest -u admin:password \
  -H "Content-Type: text/plain" \
  -d "{i01:[0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02],i02:[0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07],i03:[0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00],i0a:0xff}" \
  "http://192.168.88.1/poe.b"
```

#### Example: Set SNMP Community

```bash
# 1. GET current config
curl --digest -u admin:password "http://192.168.88.1/snmp.b"
# Response: {i01:0x01,i02:'7075626c6963',i03:'',i04:''}

# 2. Change i02 to "private" (hex: '70726976617465')
curl --digest -u admin:password \
  -H "Content-Type: text/plain" \
  -d "{i01:0x01,i02:'70726976617465',i03:'',i04:''}" \
  "http://192.168.88.1/snmp.b"
```

#### Example: Set System Identity and Static IP

```bash
# 1. GET current config
curl --digest -u admin:password "http://192.168.88.1/sys.b"

# 2. Change identity to "Switch-01" and static IP to 192.168.88.1
# Identity "Switch-01" = hex: '537769746368253041'
# IP 192.168.88.1 = little-endian: 0x0158a8c0
# Note: Send all writable fields (browser behavior)
curl --digest -u admin:password \
  -H "Content-Type: text/plain" \
  -d "{i05:'537769746368253041',i0a:0x00,i09:0x0158a8c0,i19:0x00000000,i1a:0x00,i12:0x03ff,i1b:0x01,...}" \
  "http://192.168.88.1/sys.b"
```

## Field Reference

### link.b (Port Configuration)

| Field | Type | Description | Values |
|-------|------|-------------|--------|
| `i01` | Bitmask | Port enabled | bit 0=port1, bit 1=port2, etc. |
| `i0a` | Array | Port names | Hex-encoded strings |
| `i02` | Bitmask | Auto-negotiation | bit 0=port1, bit 1=port2, etc. |
| `i03` | Bitmask | Full duplex | bit 0=port1, bit 1=port2, etc. |
| `i05` | Array | Speed | 0x00=auto, varies by model |
| `i16` | Bitmask | Flow control TX | bit 0=port1, bit 1=port2, etc. |
| `i12` | Bitmask | Flow control RX | bit 0=port1, bit 1=port2, etc. |

**Writable fields:** i01, i0a, i02, i05, i03, i16, i12
**Read-only fields:** i06, i07, i08, i13, i14, i15 (link status, actual speed, etc.)

### poe.b (PoE Configuration)

| Field | Type | Description | Values |
|-------|------|-------------|--------|
| `i01` | Array | PoE mode | 0x00=off, 0x01=on, 0x02=auto |
| `i02` | Array | PoE priority | 0x00-0x07 (priority 1-8) |
| `i03` | Array | Voltage level | 0x00=auto, 0x01=low, 0x02=high |
| `i0a` | Bitmask | LLDP enabled | bit 0=port1, bit 1=port2, etc. (8 bits) |

**Important:** PoE arrays should only contain 8 elements (for PoE-capable ports), even if the switch has 10 ports.

**Writable fields:** i01, i02, i03, i0a
**Read-only fields:** i04 (status), i05 (current), i06 (voltage), i07 (power), i0b (LLDP power)

### lacp.b (LAG/LACP Configuration)

| Field | Type | Description | Values |
|-------|------|-------------|--------|
| `i01` | Array | LACP mode | 0x00=passive, 0x01=active, 0x02=static |
| `i03` | Array | LAG group | 0x00-0x0f (group 0-15) |

**Writable fields:** i01, i03
**Read-only fields:** i02 (trunk ID), i04 (partner MAC)

### fwd.b (VLAN/Forwarding Configuration)

| Field | Type | Description | Values |
|-------|------|-------------|--------|
| `i15` | Array | VLAN mode | 0x00=disabled, 0x01=optional, 0x02=strict |
| `i17` | Array | VLAN receive | 0x00=any, 0x01=only tagged, 0x02=only untagged |
| `i18` | Array | Default VLAN ID | 0x0001-0x0fff (1-4095) |
| `i19` | Bitmask | Force VLAN ID | bit 0=port1, bit 1=port2, etc. |

**Writable fields (VLAN):** i15, i17, i18, i19
**Other writable fields:** i10-i14 (port lock, mirroring), i1a-i1e (rate limiting)
**Read-only fields:** i01-i0a (port isolation), many others

### snmp.b (SNMP Configuration)

| Field | Type | Description | Values |
|-------|------|-------------|--------|
| `i01` | Scalar | SNMP enabled | 0x00=disabled, 0x01=enabled |
| `i02` | String | Community string | Hex-encoded string (max 63 chars) |
| `i03` | String | Contact info | Hex-encoded string (max 63 chars) |
| `i04` | String | Location | Hex-encoded string (max 63 chars) |

**Writable fields:** i01, i02, i03, i04 (all fields)

### sys.b (System Configuration)

| Field | Type | Description | Values |
|-------|------|-------------|--------|
| `i05` | String | Identity/device name | Hex-encoded string (max 63 chars) |
| `i0a` | Scalar | Address acquisition mode | 0x00=DHCP with fallback, 0x01=static, 0x02=DHCP only |
| `i09` | IP | Static/fallback IP address | Little-endian encoded IP (see note below) |
| `i19` | IP | Allow From IP | Little-endian encoded IP (0x00000000 = no restriction) |
| `i1a` | Scalar | Allow From CIDR bits | 0x00-0x20 (0-32, use with i19) |
| `i12` | Bitmask | Allow From Ports | bit 0=port1, bit 1=port2, etc. (10 bits) |
| `i1b` | Scalar | Allow From VLAN | 0x0001-0x0fff (1-4095) |

**Important IP Encoding Note:**

SwOS uses **little-endian byte order** for IP addresses, which is the reverse of typical network byte order:

- IP address `192.168.88.1` is stored as `0x0158a8c0` (NOT `0xc0a85801`)
- Encoding: `192 | (168 << 8) | (88 << 16) | (1 << 24)` = `0xc0 | 0xa800 | 0x580000 | 0x01000000` = `0x0158a8c0`
- Decoding: `val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, (val >> 24) & 0xFF` = `192, 168, 88, 1`

**Writable fields:** i05, i0a, i09, i19, i1a, i12, i1b
**Read-only fields:** i01 (uptime), i03 (MAC), i04 (serial), i06 (version), i07 (model), and many others (IGMP, MDP, RSTP settings)

## Parsing Responses

The response format uses JavaScript object notation. To parse:

1. Extract the object between `{` and `}`
2. Parse key-value pairs separated by commas
3. Handle arrays: `[val1,val2,...]`
4. Handle hex numbers: `0x03ff`
5. Handle hex strings: `'506f727431'`

**Python Example:**

```python
import re

def parse_hex_value(val):
    if val.startswith("'"):
        # Hex-encoded string
        hex_str = val.strip("'")
        return bytes.fromhex(hex_str).decode('ascii', errors='ignore')
    elif val.startswith('0x'):
        # Hex number
        return int(val, 16)
    elif val.startswith('['):
        # Array
        items = re.findall(r"(?:0x[0-9a-f]+|'[0-9a-f]*')", val)
        return [parse_hex_value(item) for item in items]
    return val

def parse_js_object(text):
    # Simple parser for SwOS format
    data = {}
    # Extract key:value pairs
    pattern = r'([a-z0-9]+):(\[.*?\]|0x[0-9a-f]+|\'[0-9a-f]*\')'
    for match in re.finditer(pattern, text, re.IGNORECASE):
        key, value = match.groups()
        data[key] = parse_hex_value(value)
    return data
```

## Building POST Requests

**Python Example:**

```python
def encode_hex_string(s):
    """Encode ASCII string to hex"""
    return s.encode('ascii').hex()

def to_hex(val):
    """Convert value to SwOS hex format"""
    if isinstance(val, list):
        # Arrays: 2-digit hex for ints, strings as-is
        return '[' + ','.join(
            f'0x{v:02x}' if isinstance(v, int) else f"'{v}'"
            for v in val
        ) + ']'
    elif isinstance(val, int):
        # Scalars/bitmasks: even-length hex (browser's Ha() function logic)
        # CRITICAL: Must use even-length hex or switch parser fails!
        hex_str = f'{val:x}'
        if len(hex_str) % 2 == 1:
            hex_str = '0' + hex_str
        return f'0x{hex_str}'
    else:
        # Strings
        return f"'{val}'"

def build_post_data(fields_dict):
    """Build POST data string"""
    pairs = [f'{k}:{to_hex(v)}' for k, v in fields_dict.items()]
    return '{' + ','.join(pairs) + '}'

# Example usage
data = {
    'i01': 0x3ff,           # Bitmask
    'i0a': ['506f727431'],  # Hex string array
    'i02': 0xff,            # Scalar
    'i05': [0x00, 0x01]     # Numeric array
}
post_body = build_post_data(data)
# Result: {i01:0x03ff,i0a:['506f727431'],i02:0xff,i05:[0x00,0x01]}
```

## Important Notes

1. **Always GET before POST** - Read current config to get all field values
2. **Send complete arrays** - When modifying one port, send all ports in the array
3. **Bitmasks are per-port** - Each bit represents a port (bit 0 = port 1, etc.)
4. **Array indexes are 0-based** - Port 1 is array index 0
5. **PoE is special** - Only send first 8 array elements (PoE-capable ports)
6. **Read-only fields** - Don't send status, statistics, or calculated fields
7. **Even-length hex format** - CRITICAL: Scalars must use even-length hex (e.g., `0x03ff` not `0x3ff`, `0x00` not `0x0`). Arrays use fixed 2-digit hex (`0x02`). The switch's parser will fail or misinterpret odd-length hex values!
8. **Content-Type matters** - Must use `text/plain`
9. **No empty responses** - Successful POST returns empty body with 200 OK

## Discovering New Fields

To implement new functionality:

1. **Check engine.js** - Download and decompress: `curl --compressed http://192.168.88.1/engine.js`
2. **Find the page definition** - Search for `W("PageName"`
3. **Identify field IDs** - Look for `id:"iXX"` in the field definitions
4. **Check field types** - `t:D` (checkbox), `t:E` (dropdown), `t:I` (string), `t:F` (number)
5. **Check read-only** - Fields with `g:1` are read-only (GET-only)
6. **Capture browser POST** - Use browser DevTools to see exact POST format
7. **Match field IDs** - Browser POST shows which fields are writable

**Example from engine.js:**

```javascript
W("SNMP",Fb("snmp.b","",{},
  {n:"Enabled",t:D,id:"i01"},
  {n:"Community",t:I,id:"i02",W:63},
  {n:"Contact Info",t:I,id:"i03",W:63},
  {n:"Location",t:I,id:"i04",W:63}
))
```

This tells you:

- Endpoint: `snmp.b`
- i01: "Enabled" checkbox (t:D)
- i02: "Community" string (t:I, max 63 chars)
- i03: "Contact Info" string
- i04: "Location" string
- All writable (no `g:1` flag)
