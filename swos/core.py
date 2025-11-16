#!/usr/bin/env python3
"""
Core utility functions for SwOS/SwOS Lite API

These functions are platform-agnostic and work identically for both SwOS and SwOS Lite.
"""

import re
import binascii


def parse_js_object(text):
    """
    Parse JavaScript-like object notation to Python dict/list

    Handles formats like:
    - {i01:0x1234,i02:'hexstring'}
    - {id:'hexstring',ver:'322e3230'}
    - [{i01:1,i02:2},{i01:3,i02:4}]

    Works for both SwOS Lite (hex field IDs) and SwOS (descriptive field names).
    """
    # Replace JavaScript hex numbers with decimal
    def hex_to_int(match):
        return str(int(match.group(1), 16))

    # Convert 0x notation to integers
    text = re.sub(r'0x([0-9a-fA-F]+)', hex_to_int, text)

    # Replace single quotes with double quotes
    text = text.replace("'", '"')

    # Add quotes around keys (i01, i02, id, ver, etc.)
    text = re.sub(r'([a-zA-Z_][a-zA-Z0-9_]*):', r'"\1":', text)

    # Now it should be valid JSON
    import json
    return json.loads(text)


def decode_hex_string(hex_str):
    """
    Decode a hex-encoded ASCII string

    Example: '506f727431' -> 'Port1'
    """
    try:
        return binascii.unhexlify(hex_str).decode('ascii', errors='ignore')
    except:
        return hex_str


def encode_hex_string(text):
    """
    Encode an ASCII string to hex for wire format

    Example: 'Port1' -> '506f727431'
    """
    return binascii.hexlify(text.encode('ascii')).decode('ascii')


def decode_mac_address(hex_str):
    """
    Decode a hex-encoded MAC address

    Example: '48a98a1954b4' -> '48:a9:8a:19:54:b4'
    """
    if len(hex_str) == 12:
        return ':'.join(hex_str[i:i+2] for i in range(0, 12, 2))
    return hex_str


def encode_mac_address(mac_str):
    """
    Encode a MAC address to hex format

    Example: '48:a9:8a:19:54:b4' -> '48a98a1954b4'
    """
    return mac_str.replace(':', '').replace('-', '').lower()


def decode_ip_address_le(ip_int):
    """
    Decode a little-endian IP address

    SwOS uses little-endian byte order:
    192.168.88.1 -> 0x0158a8c0
    (192 in LSB, 1 in MSB)
    """
    return f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"


def encode_ip_address_le(ip_str):
    """
    Encode an IP address as little-endian integer

    Example: '192.168.88.1' -> 0x0158a8c0
    """
    parts = ip_str.split('.')
    if len(parts) != 4:
        raise ValueError(f"Invalid IP address: {ip_str}")

    try:
        # Little-endian: first octet in LSB
        return int(parts[0]) | (int(parts[1]) << 8) | (int(parts[2]) << 16) | (int(parts[3]) << 24)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip_str}")


def decode_port_mask(mask, num_ports):
    """
    Convert a port bitmask to a list of port numbers

    Example: 0x03ff (10 ports) -> [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    Example: 0x001f (5 ports) -> [1, 2, 3, 4, 5]
    """
    ports = []
    for i in range(num_ports):
        if mask & (1 << i):
            ports.append(i + 1)  # 1-based port numbers
    return ports


def encode_port_mask(port_list, num_ports=None):
    """
    Convert a list of port numbers to a bitmask

    Example: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] -> 0x03ff
    Example: [1, 5, 6] -> 0x0031
    """
    mask = 0
    for port_num in port_list:
        if port_num < 1:
            raise ValueError(f"Port number must be >= 1, got {port_num}")
        if num_ports and port_num > num_ports:
            raise ValueError(f"Port number {port_num} exceeds max ports {num_ports}")
        mask |= (1 << (port_num - 1))  # Convert 1-based to 0-based
    return mask


def _format_hex_value(val):
    """
    Format a number as even-length hex for POST requests

    Browser's Ha() function logic:
    - Converts to hex string
    - If odd length, prepends '0' to make it even
    - Adds '0x' prefix

    Examples:
        0 -> "0x00"
        255 -> "0x00ff"
        1023 -> "0x03ff"
        959 -> "0x03bf"
    """
    hex_str = f'{val:x}'
    if len(hex_str) % 2 == 1:
        hex_str = '0' + hex_str
    return f'0x{hex_str}'


def format_post_value(val):
    """
    Format a value for POST request body

    Handles:
    - Arrays: [value, value, ...]
    - Integers/bitmasks: 0xXXXX (even-length hex)
    - Strings: 'hexstring'
    """
    if isinstance(val, list):
        # For arrays: use 2-digit hex for ints, strings stay as-is
        formatted = []
        for v in val:
            if isinstance(v, int):
                formatted.append(f'0x{v:02x}')
            else:
                formatted.append(f"'{v}'")
        return '[' + ','.join(formatted) + ']'
    elif isinstance(val, int):
        # For scalars/bitmasks: use even-length hex
        return _format_hex_value(val)
    else:
        # For strings: wrap in quotes
        return f"'{val}'"


def build_post_data(data_dict):
    """
    Build POST request body from a dictionary

    Example:
        {'i01': 0x03ff, 'i0a': ['506f727431', '506f727432']}
        ->
        "{i01:0x03ff,i0a:['506f727431','506f727432']}"
    """
    pairs = [f'{k}:{format_post_value(v)}' for k, v in data_dict.items()]
    return '{' + ','.join(pairs) + '}'


def build_post_array(array_of_dicts):
    """
    Build POST request body for array of objects (e.g., VLANs)

    Example:
        [{'i01': 1, 'i02': 0x03ff}, {'i01': 10, 'i02': 0x0030}]
        ->
        "[{i01:0x0001,i02:0x03ff},{i01:0x000a,i02:0x0030}]"
    """
    obj_strings = []
    for obj in array_of_dicts:
        pairs = [f'{k}:{format_post_value(v)}' for k, v in obj.items()]
        obj_strings.append('{' + ','.join(pairs) + '}')
    return '[' + ','.join(obj_strings) + ']'
