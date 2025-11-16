#!/usr/bin/env python3
"""
Platform detection and adapter for SwOS/SwOS Lite

Provides automatic platform detection and a unified interface for
interacting with both SwOS and SwOS Lite devices.
"""

import requests
from requests.auth import HTTPDigestAuth
from typing import Tuple, Optional

from .core import parse_js_object, decode_hex_string
from .field_maps import FieldMap, get_field
from .css_map import CSS_FIELD_MAP
from .swos_map import SWOS_FIELD_MAP


class PlatformType:
    """Platform type constants"""
    SWOS_LITE = "swos-lite"
    SWOS = "swos"
    ROUTEROS = "routeros"
    UNKNOWN = "unknown"


def detect_platform_from_data(data: dict) -> str:
    """
    Detect platform type from parsed sys.b data

    Args:
        data: Parsed sys.b response

    Returns:
        PlatformType constant (SWOS_LITE, SWOS, or UNKNOWN)
    """
    # Method 1: Check field name format
    # SwOS Lite uses hex IDs (i01, i05, i06, etc.)
    # SwOS uses descriptive names (id, ver, brd, etc.)
    has_hex_fields = any(k.startswith('i') and len(k) == 3 for k in data.keys())
    has_descriptive_fields = 'id' in data or 'ver' in data or 'brd' in data

    if has_hex_fields and not has_descriptive_fields:
        return PlatformType.SWOS_LITE
    elif has_descriptive_fields and not has_hex_fields:
        return PlatformType.SWOS

    # Method 2: Check model string as fallback
    # Try SwOS Lite model field first
    model_hex = data.get('i07') or data.get('brd', '')
    if model_hex:
        model = decode_hex_string(model_hex)
        if model.startswith('CSS'):
            return PlatformType.SWOS_LITE
        elif model.startswith('CRS') or model.startswith('RB'):
            return PlatformType.SWOS

    # Method 3: Check version string
    ver_hex = data.get('i06') or data.get('ver', '')
    if ver_hex:
        version = decode_hex_string(ver_hex)
        if 'lite' in version.lower():
            return PlatformType.SWOS_LITE

    return PlatformType.UNKNOWN


def is_routeros(url: str, username: str, password: str) -> bool:
    """
    Check if device is running RouterOS

    RouterOS has a /graphs/ endpoint that returns 200, while SwOS/SwOS Lite redirect to index.html

    Args:
        url: Device URL
        username: Username
        password: Password

    Returns:
        True if RouterOS, False otherwise
    """
    try:
        auth = HTTPDigestAuth(username, password)
        url_base = url.rstrip('/')
        response = requests.get(f"{url_base}/graphs/", auth=auth, timeout=5, verify=False,
                              allow_redirects=False)

        # RouterOS returns 200 for /graphs/
        # SwOS/SwOS Lite redirect (303) to index.html
        if response.status_code == 200 and 'graph' in response.text.lower():
            return True
        return False
    except:
        return False


def detect_platform(url: str, username: str, password: str) -> str:
    """
    Detect platform type by querying device endpoints

    Args:
        url: Switch URL (e.g., 'http://192.168.88.1' or 'https://192.168.88.1:8443')
        username: Username for authentication
        password: Password for authentication

    Returns:
        PlatformType constant (SWOS_LITE, SWOS, ROUTEROS, or UNKNOWN)

    Raises:
        RuntimeError: If connection fails
    """
    # First check if it's RouterOS
    if is_routeros(url, username, password):
        return PlatformType.ROUTEROS

    # Try to query sys.b for SwOS/SwOS Lite
    try:
        auth = HTTPDigestAuth(username, password)
        url_base = url.rstrip('/')
        response = requests.get(f"{url_base}/sys.b", auth=auth, timeout=10, verify=False)
        response.raise_for_status()

        # Try to parse as JavaScript object notation
        try:
            data = parse_js_object(response.text)
            return detect_platform_from_data(data)
        except:
            return PlatformType.UNKNOWN

    except Exception as e:
        raise RuntimeError(f"Failed to detect platform: {e}")


def get_field_map(platform_type: str) -> FieldMap:
    """
    Get field map for the specified platform

    Args:
        platform_type: PlatformType constant

    Returns:
        FieldMap instance for the platform

    Raises:
        ValueError: If platform type is unsupported
    """
    if platform_type == PlatformType.SWOS_LITE:
        return CSS_FIELD_MAP
    elif platform_type == PlatformType.SWOS:
        return SWOS_FIELD_MAP
    elif platform_type == PlatformType.ROUTEROS:
        raise ValueError("RouterOS is not yet supported. RouterOS uses a different REST API. "
                       "This library only supports SwOS and SwOS Lite.")
    else:
        raise ValueError(f"Unknown platform type: {platform_type}")


def get_port_count_from_link_data(link_data: dict, platform_type: str) -> int:
    """
    Determine port count from link.b response

    Args:
        link_data: Parsed link.b response
        platform_type: Platform type

    Returns:
        Number of ports on the switch
    """
    if platform_type == PlatformType.SWOS:
        # SwOS has explicit 'prt' field
        port_count = link_data.get('prt')
        if port_count:
            return port_count

    # Fall back to port names array length (works for both platforms)
    field_map = get_field_map(platform_type)
    port_names = link_data.get(field_map.port_names, [])
    return len(port_names)


class PlatformAdapter:
    """
    Platform adapter that auto-detects and provides unified interface

    This adapter automatically detects the platform type and provides
    a consistent interface for accessing device configuration regardless
    of whether it's SwOS or SwOS Lite.
    """

    def __init__(self, url: str, username: str, password: str, platform_type: Optional[str] = None):
        """
        Initialize platform adapter

        Args:
            url: Switch URL (e.g., 'http://192.168.88.1' or 'https://192.168.88.1:8443')
            username: Username for authentication
            password: Password for authentication
            platform_type: Optional platform type override (auto-detect if None)

        Raises:
            RuntimeError: If platform cannot be detected or is unsupported
        """
        self.url = url.rstrip('/')  # Remove trailing slash
        self.username = username
        self.password = password
        self.auth = HTTPDigestAuth(username, password)

        # Detect or use provided platform type
        if platform_type:
            self.platform_type = platform_type
        else:
            self.platform_type = detect_platform(url, username, password)

        if self.platform_type == PlatformType.ROUTEROS:
            raise RuntimeError(
                "RouterOS detected. This library only supports SwOS and SwOS Lite. "
                "RouterOS uses a different REST API (/rest/...)."
            )

        if self.platform_type == PlatformType.UNKNOWN:
            raise RuntimeError("Unable to detect platform type")

        # Load appropriate field map
        self.field_map = get_field_map(self.platform_type)

        # Cache for device capabilities
        self._port_count = None
        self._has_poe = None
        self._has_lacp = None
        self._has_snmp = None

    def get_endpoint_url(self, endpoint_name: str) -> str:
        """
        Get full URL for an endpoint

        Args:
            endpoint_name: Logical endpoint name (e.g., 'system', 'link', 'vlan_table')

        Returns:
            Full URL for the endpoint
        """
        endpoint_attr = f"endpoint_{endpoint_name}"
        endpoint = getattr(self.field_map, endpoint_attr, None)
        if not endpoint:
            raise ValueError(f"Unknown endpoint: {endpoint_name}")
        return f"{self.url}/{endpoint}"

    def get_port_count(self) -> int:
        """
        Get number of ports on the switch

        Returns:
            Number of ports (cached after first call)
        """
        if self._port_count is None:
            try:
                response = requests.get(self.get_endpoint_url('link'), auth=self.auth,
                                      timeout=10, verify=False)
                response.raise_for_status()
                data = parse_js_object(response.text)
                self._port_count = get_port_count_from_link_data(data, self.platform_type)
            except:
                # Default fallback
                self._port_count = 10
        return self._port_count

    def has_feature(self, endpoint_name: str) -> bool:
        """
        Check if a feature is supported by querying its endpoint

        Args:
            endpoint_name: Logical endpoint name (e.g., 'poe', 'lag', 'snmp')

        Returns:
            True if feature is supported, False otherwise
        """
        try:
            url = self.get_endpoint_url(endpoint_name)
            response = requests.get(url, auth=self.auth, timeout=5, verify=False)

            # Check if we got actual data (not a redirect to index.html)
            if response.status_code == 200 and response.text:
                # Try to parse - if it parses, feature is supported
                data = parse_js_object(response.text)
                return bool(data)  # Has content = supported
            return False
        except:
            return False

    def has_poe(self) -> bool:
        """Check if switch has PoE support (cached)"""
        if self._has_poe is None:
            self._has_poe = self.has_feature('poe')
        return self._has_poe

    def has_lacp(self) -> bool:
        """Check if switch has LAG/LACP support (cached)"""
        if self._has_lacp is None:
            self._has_lacp = self.has_feature('lag')
        return self._has_lacp

    def has_snmp(self) -> bool:
        """Check if switch has SNMP support (cached)"""
        if self._has_snmp is None:
            self._has_snmp = self.has_feature('snmp')
        return self._has_snmp

    def get(self, endpoint_name: str) -> dict:
        """
        GET request to an endpoint

        Args:
            endpoint_name: Logical endpoint name

        Returns:
            Parsed response data

        Raises:
            requests.HTTPError: If request fails
        """
        url = self.get_endpoint_url(endpoint_name)
        response = requests.get(url, auth=self.auth, timeout=10, verify=False)
        response.raise_for_status()
        return parse_js_object(response.text)

    def post(self, endpoint_name: str, data: str) -> str:
        """
        POST request to an endpoint

        Args:
            endpoint_name: Logical endpoint name
            data: POST body (formatted string)

        Returns:
            Response text

        Raises:
            requests.HTTPError: If request fails
        """
        url = self.get_endpoint_url(endpoint_name)
        response = requests.post(url, data=data, auth=self.auth,
                               headers={'Content-Type': 'text/plain'},
                               timeout=10, verify=False)
        response.raise_for_status()
        return response.text

    def __repr__(self):
        return f"PlatformAdapter(platform={self.field_map.platform_name}, url={self.url})"
