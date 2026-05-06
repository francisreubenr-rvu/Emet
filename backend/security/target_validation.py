from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import re
from urllib.parse import urlparse


HOST_PATTERN = re.compile(r"^[a-zA-Z0-9.-]+$")


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _extract_host(target: str) -> str:
    value = target.strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        return (parsed.hostname or "").strip()
    return value.split("/")[0].split(":")[0].strip()


def _is_blocked_ip(ip: ipaddress._BaseAddress, allow_internal: bool) -> bool:
    if ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_unspecified or ip.is_link_local:
        return True
    if ip.is_private and not allow_internal:
        return True
    if getattr(ip, "is_site_local", False) and not allow_internal:
        return True
    return False


def _validate_hostname(host: str) -> tuple[bool, str]:
    if not HOST_PATTERN.match(host):
        return False, "Invalid hostname format"
    labels = host.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False, "Invalid hostname label"
        if label.startswith("-") or label.endswith("-"):
            return False, "Hostname labels cannot start/end with dash"
    return True, "ok"


def validate_target(target: str) -> tuple[bool, str]:
    if target.strip().startswith("-"):
        return False, "Target cannot start with a hyphen (argument injection prevented)"
        
    host = _extract_host(target)
    if not host:
        return False, "Target host is missing"

    allow_internal = _bool_env("ALLOW_INTERNAL_SCANNING", default=False)

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        valid, reason = _validate_hostname(host)
        if not valid:
            return False, reason
            
        import socket
        try:
            resolved_ip = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved_ip)
        except socket.gaierror:
            return False, "Could not resolve hostname"

    if _is_blocked_ip(ip, allow_internal=allow_internal):
        if ip.is_private and not allow_internal:
            return False, "Private/internal targets are blocked unless ALLOW_INTERNAL_SCANNING=true"
        return False, "Target IP is blocked by safety policy"
    return True, "ok"


def validate_repo_target(target: str) -> tuple[bool, str]:
    value = target.strip()
    if value.startswith("repo:"):
        raw = value.split("repo:", 1)[1]
    elif value.startswith("file://"):
        raw = urlparse(value).path
    else:
        return False, "Repository target must start with repo: or file://"

    if _bool_env("EMET_SIMULATE_SCANS", default=False):
        return True, "ok"

    candidate = Path(raw).expanduser().resolve()
    root = Path(os.getenv("SCAN_REPO_ALLOWED_ROOT", "/app")).expanduser().resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return False, "Repository target is outside SCAN_REPO_ALLOWED_ROOT"
    if not candidate.exists() or not candidate.is_dir():
        return False, "Repository target path not found"
    return True, "ok"
