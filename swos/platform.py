#!/usr/bin/env python3
"""
Platform detection and adapter for SwOS/SwOS Lite.

Provides automatic platform detection and a unified interface for interacting
with both SwOS and SwOS Lite devices.
"""

import requests
from requests.auth import HTTPDigestAuth
from typing import Optional

from .core import parse_js_object, decode_hex_string
from .field_maps import FieldMap
from .swos_lite_map import SWOS_LITE_FIELD_MAP
from .swos_map import SWOS_FIELD_MAP


class PlatformType:
    """Platform type constants"""
    SWOS_LITE = "swos-lite"
    SWOS = "swos"
    ROUTEROS = "routeros"
    UNKNOWN = "unknown"


def detect_platform_from_data(data: dict) -> str:
    """
    Detect platform type from parsed sys.b data.

    Detection priority:
    1. Field naming convention (authoritative)
    2. Version string hints
    3. Model string hints (conservative only)

    Important:
    CSS model prefix is NOT sufficient to infer SwOS Lite, because CSS326
    runs full SwOS and exposes descriptive fields such as id/ver/brd.
    """

    keys = set(data.keys())

    # SwOS Lite uses field IDs like i01, i05, i06, ...
    # SwOS uses descriptive names like id, ver, brd, ...
    has_lite_style_fields = any(
        len(k) == 3 and k[0] == "i" and k[1:].isdigit()
        for k in keys
    )
    has_swos_style_fields = any(k in keys for k in ("id", "ver", "brd"))

    if has_swos_style_fields and not has_lite_style_fields:
        return PlatformType.SWOS

    if has_lite_style_fields and not has_swos_style_fields:
        return PlatformType.SWOS_LITE

    # Version hint
    ver_raw = data.get("i06") or data.get("ver") or ""
    version = decode_hex_string(ver_raw) if ver_raw else ""
    if version and "lite" in version.lower():
        return PlatformType.SWOS_LITE

    # Conservative model fallback
    model_raw = data.get("i07") or data.get("brd") or ""
    model = decode_hex_string(model_raw) if model_raw else ""

    if model.startswith("CRS") or model.startswith("RB"):
        return PlatformType.SWOS

    if model.startswith("CSS") and has_swos_style_fields:
        return PlatformType.SWOS

    if model.startswith("CSS") and has_lite_style_fields:
        return PlatformType.SWOS_LITE

    return PlatformType.UNKNOWN


def is_routeros(url: str, username: str, password: str) -> bool:
    """
    Check if device is running RouterOS.

    RouterOS has a /graphs/ endpoint that returns 200,
    while SwOS/SwOS Lite redirect to index.html.
    """
    try:
        auth = HTTPDigestAuth(username, password)
        url_base = url.rstrip("/")
        response = requests.get(
            f"{url_base}/graphs/",
            auth=auth,
            timeout=5,
            verify=False,
            allow_redirects=False,
        )

        if response.status_code == 200 and "graph" in response.text.lower():
            return True
        return False
    except Exception:
        return False


def detect_platform(url: str, username: str, password: str) -> str:
    """
    Detect platform type by querying device endpoints.
    """
    if is_routeros(url, username, password):
        return PlatformType.ROUTEROS

    try:
        auth = HTTPDigestAuth(username, password)
        url_base = url.rstrip("/")
        response = requests.get(
            f"{url_base}/sys.b",
            auth=auth,
            timeout=10,
            verify=False,
        )
        response.raise_for_status()

        try:
            data = parse_js_object(response.text)
            return detect_platform_from_data(data)
        except Exception:
            return PlatformType.UNKNOWN

    except Exception as e:
        raise RuntimeError(f"Failed to detect platform: {e}")


def get_field_map(platform_type: str) -> FieldMap:
    """
    Get field map for the specified platform.
    """
    if platform_type == PlatformType.SWOS_LITE:
        return SWOS_LITE_FIELD_MAP
    elif platform_type == PlatformType.SWOS:
        return SWOS_FIELD_MAP
    elif platform_type == PlatformType.ROUTEROS:
        raise ValueError(
            "RouterOS is not yet supported. "
            "RouterOS uses a different REST API. "
            "This library only supports SwOS and SwOS Lite."
        )
    else:
        raise ValueError(f"Unknown platform type: {platform_type}")


def get_port_count_from_link_data(link_data: dict, platform_type: str) -> int:
    """
    Determine port count from link.b response.
    """
    if platform_type == PlatformType.SWOS:
        port_count = link_data.get("prt")
        if port_count:
            return port_count

    field_map = get_field_map(platform_type)
    port_names = link_data.get(field_map.port_names, [])
    return len(port_names)


class PlatformAdapter:
    """
    Platform adapter that auto-detects and provides unified interface.
    """

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        platform_type: Optional[str] = None,
    ):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.auth = HTTPDigestAuth(username, password)

        if platform_type:
            self.platform_type = platform_type
        else:
            self.platform_type = detect_platform(url, username, password)

        if self.platform_type == PlatformType.ROUTEROS:
            raise RuntimeError(
                "RouterOS detected. "
                "This library only supports SwOS and SwOS Lite. "
                "RouterOS uses a different REST API (/rest/...)."
            )

        if self.platform_type == PlatformType.UNKNOWN:
            raise RuntimeError("Unable to detect platform type")

        self.field_map = get_field_map(self.platform_type)

        self._port_count = None
        self._has_poe = None
        self._has_lacp = None
        self._has_snmp = None

    def get_endpoint_url(self, endpoint_name: str) -> str:
        endpoint_attr = f"endpoint_{endpoint_name}"
        endpoint = getattr(self.field_map, endpoint_attr, None)
        if not endpoint:
            raise ValueError(f"Unknown endpoint: {endpoint_name}")
        return f"{self.url}/{endpoint}"

    def get_port_count(self) -> int:
        if self._port_count is None:
            try:
                response = requests.get(
                    self.get_endpoint_url("link"),
                    auth=self.auth,
                    timeout=10,
                    verify=False,
                )
                response.raise_for_status()
                data = parse_js_object(response.text)
                self._port_count = get_port_count_from_link_data(
                    data, self.platform_type
                )
            except Exception:
                self._port_count = 10
        return self._port_count

    def has_feature(self, endpoint_name: str) -> bool:
        try:
            url = self.get_endpoint_url(endpoint_name)
            response = requests.get(
                url,
                auth=self.auth,
                timeout=5,
                verify=False,
            )
            if response.status_code == 200 and response.text:
                data = parse_js_object(response.text)
                return bool(data)
            return False
        except Exception:
            return False

    def has_poe(self) -> bool:
        if self._has_poe is None:
            self._has_poe = self.has_feature("poe")
        return self._has_poe

    def has_lacp(self) -> bool:
        if self._has_lacp is None:
            self._has_lacp = self.has_feature("lag")
        return self._has_lacp

    def has_snmp(self) -> bool:
        if self._has_snmp is None:
            self._has_snmp = self.has_feature("snmp")
        return self._has_snmp

    def get(self, endpoint_name: str) -> dict:
        url = self.get_endpoint_url(endpoint_name)
        response = requests.get(
            url,
            auth=self.auth,
            timeout=10,
            verify=False,
        )
        response.raise_for_status()
        return parse_js_object(response.text)

    def post(self, endpoint_name: str, data: str) -> str:
        url = self.get_endpoint_url(endpoint_name)
        response = requests.post(
            url,
            data=data,
            auth=self.auth,
            headers={"Content-Type": "text/plain"},
            timeout=10,
            verify=False,
        )
        response.raise_for_status()
        return response.text

    def __repr__(self):
        return f"PlatformAdapter(platform={self.field_map.platform_name}, url={self.url})"
