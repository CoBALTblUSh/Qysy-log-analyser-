#!/usr/bin/env python3
"""
Q-SYS Log Dashboard
===================
A dependency-free local web dashboard for Q-SYS .qsyslog diagnostic archives.

Run from PyCharm or a terminal:
    python qsys_log_dashboard.py
    python qsys_log_dashboard.py /path/to/device.qsyslog

The script opens a local browser at http://127.0.0.1:<port>.
Nothing is uploaded to the internet.
"""

from __future__ import annotations

import argparse
import html
import io
import json
import mimetypes
import os
import re
import shutil
import socket
import tarfile
import tempfile
import threading
import time
import traceback
import urllib.parse
import webbrowser
import zipfile
from dataclasses import asdict, dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Optional

APP_NAME = "Q-SYS Log Dashboard"
APP_VERSION = "1.0.0"
MAX_UPLOAD_BYTES = 250 * 1024 * 1024
MAX_EXTRACTED_BYTES = 750 * 1024 * 1024
MAX_ARCHIVE_FILES = 20_000
MAX_SINGLE_FILE_BYTES = 75 * 1024 * 1024
MAX_TEXT_FILE_BYTES = 15 * 1024 * 1024
MAX_EVENTS = 300_000
DEFAULT_PAGE_SIZE = 150

TIMESTAMP_PATTERNS = [
    re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)"),
    re.compile(r"^\[(?P<ts>\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\]"),
    re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
]

SEVERITY_ORDER = {"critical": 0, "error": 1, "warning": 2, "info": 3, "debug": 4}


@dataclass(slots=True)
class Event:
    index: int
    timestamp: str
    severity: str
    category: str
    source: str
    line_number: int
    message: str


@dataclass(slots=True)
class FileInfo:
    path: str
    size: int
    kind: str
    text: bool
    event_source: bool


class DashboardState:
    """Thread-safe holder for the currently loaded archive."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.dataset: Optional[QsysDataset] = None
        self.last_error: Optional[str] = None

    def replace(self, dataset: "QsysDataset") -> None:
        with self.lock:
            old = self.dataset
            self.dataset = dataset
            self.last_error = None
        if old:
            old.close()

    def set_error(self, message: str) -> None:
        with self.lock:
            self.last_error = message


class QsysDataset:
    def __init__(self, source_path: Path) -> None:
        self.source_path = source_path
        self.temp_dir = Path(tempfile.mkdtemp(prefix="qsys-dashboard-"))
        self.root = self.temp_dir / "extracted"
        self.root.mkdir(parents=True, exist_ok=True)
        self.files: list[FileInfo] = []
        self.events: list[Event] = []
        self.properties: dict[str, str] = {}
        self.metadata: dict[str, Any] = {}
        self.stats: dict[str, Any] = {}
        self.findings: list[dict[str, Any]] = []
        self.loaded_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self._extract_source()
        self._inventory_files()
        self._parse_properties()
        self._parse_events()
        self._build_metadata()
        self._build_findings()
        self._build_stats()

    def close(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # ------------------------------ Extraction ------------------------------

    @staticmethod
    def _safe_archive_name(name: str) -> Optional[Path]:
        name = name.replace("\\", "/")
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts:
            return None
        parts = [p for p in pure.parts if p not in ("", ".")]
        return Path(*parts) if parts else None

    def _extract_source(self) -> None:
        source = self.source_path
        if source.is_dir():
            shutil.copytree(source, self.root, dirs_exist_ok=True)
            return

        if zipfile.is_zipfile(source):
            total = 0
            with zipfile.ZipFile(source) as archive:
                infos = archive.infolist()
                if len(infos) > MAX_ARCHIVE_FILES:
                    raise ValueError(f"Archive contains too many files ({len(infos):,}).")
                for info in infos:
                    if info.is_dir():
                        continue
                    rel = self._safe_archive_name(info.filename)
                    if not rel:
                        continue
                    if info.file_size > MAX_SINGLE_FILE_BYTES:
                        continue
                    total += info.file_size
                    if total > MAX_EXTRACTED_BYTES:
                        raise ValueError("Archive exceeds the safe extraction limit.")
                    target = self.root / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as src, target.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
            return

        try:
            with tarfile.open(source, "r:*") as archive:
                members = archive.getmembers()
                if len(members) > MAX_ARCHIVE_FILES:
                    raise ValueError(f"Archive contains too many files ({len(members):,}).")
                total = 0
                for member in members:
                    if not member.isfile():
                        continue
                    rel = self._safe_archive_name(member.name)
                    if not rel:
                        continue
                    if member.size > MAX_SINGLE_FILE_BYTES:
                        continue
                    total += member.size
                    if total > MAX_EXTRACTED_BYTES:
                        raise ValueError("Archive exceeds the safe extraction limit.")
                    src = archive.extractfile(member)
                    if not src:
                        continue
                    target = self.root / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with src, target.open("wb") as dst:
                        shutil.copyfileobj(src, dst)
            return
        except tarfile.ReadError:
            pass

        # A normal text log is also accepted.
        target = self.root / source.name
        shutil.copy2(source, target)

    # ------------------------------- Reading --------------------------------

    @staticmethod
    def _is_probably_text(path: Path) -> bool:
        try:
            if path.stat().st_size == 0:
                return True
            with path.open("rb") as handle:
                chunk = handle.read(8192)
            if b"\x00" in chunk:
                return False
            printable = sum(1 for b in chunk if b in b"\n\r\t\f\b" or 32 <= b <= 126 or b >= 128)
            return printable / max(len(chunk), 1) > 0.82
        except OSError:
            return False

    @staticmethod
    def _read_text(path: Path, limit: int = MAX_TEXT_FILE_BYTES) -> str:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            data = data[:limit] + b"\n\n[Dashboard truncated this file.]\n"
        return data.decode("utf-8", errors="replace")

    def _inventory_files(self) -> None:
        for path in sorted(self.root.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(self.root).as_posix()
            size = path.stat().st_size
            text = size <= MAX_TEXT_FILE_BYTES and self._is_probably_text(path)
            event_source = text and self._is_event_source(rel)
            suffix = path.suffix.lower()
            if text:
                kind = "text"
            elif suffix in {".jpg", ".jpeg", ".png", ".gif", ".webp"}:
                kind = "image"
            else:
                kind = suffix.lstrip(".") or "binary"
            self.files.append(FileInfo(rel, size, kind, text, event_source))

    def _is_event_source(self, rel: str) -> bool:
        lower = rel.lower()
        name = Path(lower).name
        if lower == "tmp/dmesg" and (self.root / "var/log/messages").exists():
            return False  # Usually a duplicate of kernel entries in messages.
        if lower.startswith("var/log/"):
            return True
        if name in {"messages", "syslog", "dmesg", "kern.log", "event.log"}:
            return True
        if name.endswith((".log", "_log.txt", "-log.txt")):
            return True
        return False

    # ----------------------------- Data parsing ------------------------------

    def _parse_properties(self) -> None:
        candidates = [
            self.root / "var/run/properties_snapshot",
            self.root / "properties_snapshot",
        ]
        for path in candidates:
            if not path.exists():
                continue
            for line in self._read_text(path).splitlines():
                if " : " in line:
                    key, value = line.split(" : ", 1)
                    self.properties[key.strip()] = value.strip()
            break

    @staticmethod
    def _timestamp(line: str) -> str:
        for pattern in TIMESTAMP_PATTERNS:
            match = pattern.search(line)
            if match:
                return match.group("ts")
        return ""

    @staticmethod
    def _severity(line: str) -> str:
        lower = line.lower()
        # Structured syslog / Q-SYS fields first.
        if re.search(r"\b(?:emerg|alert|crit|critical|fatal)\b", lower):
            return "critical"
        if re.search(r"\b(?:kern\.)?(?:err|error)\b", lower) or "[error]" in lower:
            return "error"
        if re.search(r"\b(?:warning|warn)\b", lower) or "[warning]" in lower:
            return "warning"
        if re.search(r"\bdebug\b", lower) or "[debug]" in lower:
            return "debug"

        # Device-health phrases that do not always carry a severity token.
        critical_phrases = (
            "compromised -",
            "fan 1 stopped",
            "over temperature",
            "over-temperature",
            "thermal shutdown",
        )
        error_phrases = (
            "failed to calculate mmcm",
            "timing detector failure",
            "input/output error",
            "segmentation fault",
            "panic",
        )
        warning_phrases = (
            "scdc interception mismatch",
            "hdcp unauthenticated",
            "input_streamdown",
            "deconfiguring",
            "forced hotplug",
            "link down",
        )
        if any(p in lower for p in critical_phrases):
            return "critical"
        if any(p in lower for p in error_phrases):
            return "error"
        if any(p in lower for p in warning_phrases):
            return "warning"
        return "info"

    @staticmethod
    def _category(line: str) -> str:
        lower = line.lower()
        if any(x in lower for x in ("fan", "thermal", "temperature", "temp1_", "temp4_", "hwmon")):
            return "Cooling"
        if any(x in lower for x in ("hdmi", "scdc", "ps8409", "edid", "hdcp", "hotplug", "mmcm", "pclk")):
            return "HDMI"
        if any(x in lower for x in ("configure_encoder", "input_stream", "encoder", "rtsp://", "video-engine")):
            return "Encoder"
        if any(x in lower for x in ("poe", "power", "voltage", "802.3bt")):
            return "Power"
        if any(x in lower for x in ("ptp", "ethernet", "network", "multicast", "dscp", "packet", "lan_", "link up", "link down")):
            return "Network"
        if any(x in lower for x in ("design", "runtime_engine", "audio_engine", "core", "qsys")):
            return "Design"
        return "System"

    def _parse_events(self) -> None:
        index = 0
        for info in self.files:
            if not info.event_source:
                continue
            path = self.root / info.path
            try:
                text = self._read_text(path)
            except OSError:
                continue
            for line_number, raw_line in enumerate(text.splitlines(), start=1):
                line = raw_line.rstrip()
                if not line:
                    continue
                self.events.append(
                    Event(
                        index=index,
                        timestamp=self._timestamp(line),
                        severity=self._severity(line),
                        category=self._category(line),
                        source=info.path,
                        line_number=line_number,
                        message=line,
                    )
                )
                index += 1
                if index >= MAX_EVENTS:
                    return

    def _prop(self, *keys: str) -> str:
        for key in keys:
            value = self.properties.get(key)
            if value:
                return value
        return ""

    def _read_small_value(self, rel: str) -> str:
        path = self.root / rel
        try:
            return self._read_text(path, 4096).strip()
        except OSError:
            return ""

    @staticmethod
    def _millidegrees(value: str) -> Optional[float]:
        try:
            number = float(value.strip())
            if abs(number) > 1000:
                number /= 1000.0
            return round(number, 1)
        except (TypeError, ValueError):
            return None

    def _build_metadata(self) -> None:
        status = self._prop("/qsys/design/status")
        hostname = self._prop("/sys/lan_daemon/hostname", "/sys/net_static/hostname")
        firmware = self._prop("/sys/config/firmware_name")
        serial = self._prop("/sys/config/serial_number")
        platform = self._prop("/sys/config/platform")
        hdmi = self._prop("/sys/hdmi1_properties")

        # Common Q-SYS network property names vary by firmware.
        ip = ""
        for key, value in self.properties.items():
            key_lower = key.lower()
            if not ip and (key_lower.endswith("/ip_address") or key_lower.endswith("/ipv4_address")):
                if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}", value):
                    ip = value

        fan_rpm = self._read_small_value("tmp/sys/class/hwmon0/fan1_input")
        pwm = self._read_small_value("tmp/sys/class/hwmon0/pwm1")
        temp1 = self._millidegrees(self._read_small_value("tmp/sys/class/hwmon0/temp1_input"))
        temp1_max = self._millidegrees(self._read_small_value("tmp/sys/class/hwmon0/temp1_max"))
        temp1_crit = self._millidegrees(self._read_small_value("tmp/sys/class/hwmon0/temp1_crit"))
        temp4 = self._millidegrees(self._read_small_value("tmp/sys/class/hwmon0/temp4_input"))
        max_alarm = self._read_small_value("tmp/sys/class/hwmon0/temp1_max_alarm")

        try:
            pwm_percent = round(float(pwm) / 255 * 100) if pwm else None
        except ValueError:
            pwm_percent = None

        self.metadata = {
            "source_name": self.source_path.name,
            "hostname": hostname or "Unknown",
            "firmware": firmware or "Unknown",
            "serial": serial or "Unknown",
            "platform": platform or "Unknown",
            "ip_address": ip or "Not found",
            "design_status": status or "Not found",
            "hdmi_input_1": hdmi or "Not found",
            "fan_1_rpm": fan_rpm or "Not found",
            "fan_pwm_percent": pwm_percent,
            "temperature_1_c": temp1,
            "temperature_1_max_c": temp1_max,
            "temperature_1_critical_c": temp1_crit,
            "temperature_2_c": temp4,
            "temperature_max_alarm": max_alarm == "1",
            "loaded_at": self.loaded_at,
        }

    def _count_events(self, needle: str) -> int:
        needle = needle.lower()
        return sum(1 for event in self.events if needle in event.message.lower())

    def _matching_resolutions(self) -> list[dict[str, Any]]:
        counts: dict[str, int] = {}
        pattern = re.compile(r"dim=(\d+x\d+@\d+)", re.I)
        for event in self.events:
            match = pattern.search(event.message)
            if match and match.group(1) != "0x0@0":
                value = match.group(1)
                counts[value] = counts.get(value, 0) + 1
        return [{"resolution": key, "count": value} for key, value in sorted(counts.items(), key=lambda x: (-x[1], x[0]))]

    def _build_findings(self) -> None:
        findings: list[dict[str, Any]] = []
        status = str(self.metadata.get("design_status", ""))
        fan_rpm = str(self.metadata.get("fan_1_rpm", ""))
        temp = self.metadata.get("temperature_1_c")
        max_temp = self.metadata.get("temperature_1_max_c")

        if "fan" in status.lower() and "stopped" in status.lower() or fan_rpm == "0":
            findings.append({
                "severity": "critical",
                "title": "Fan 1 is stopped",
                "detail": f"The hardware monitor reports Fan 1 at {fan_rpm} RPM. Continued operation can cause overheating and unstable HDMI behavior.",
                "action": "Power the unit down, check ventilation, and service or replace the HU if the fan does not spin after a cold restart.",
            })
        if isinstance(temp, (int, float)) and isinstance(max_temp, (int, float)) and temp >= max_temp:
            findings.append({
                "severity": "critical",
                "title": f"Temperature reached {temp:g}°C",
                "detail": f"The measured temperature is at or above the configured {max_temp:g}°C maximum alarm point.",
                "action": "Resolve the fan fault before relying on HDMI or encoder testing.",
            })

        scdc = self._count_events("SCDC interception mismatch")
        mmcm = self._count_events("failed to calculate MMCM parameters")
        timing = self._count_events("Timing detector failure")
        stream_up = self._count_events("input_streamup")
        stream_down = self._count_events("input_streamdown")
        hdcp = self._count_events("HDCP Unauthenticated")
        configuring = sum(1 for e in self.events if "configure_encoder" in e.message and " configuring" in e.message)

        if scdc:
            findings.append({
                "severity": "error" if scdc >= 5 else "warning",
                "title": f"{scdc} HDMI SCDC mismatch reset{'s' if scdc != 1 else ''}",
                "detail": "The HDMI 2.0 source and receiver repeatedly disagreed on link/scrambling state.",
                "action": "Force the source to 1920×1080 at 60 Hz with HDR off, then test a direct known-good adapter and HDMI cable.",
            })
        if mmcm or timing:
            findings.append({
                "severity": "error",
                "title": f"HDMI timing could not be locked ({mmcm + timing} event{'s' if mmcm + timing != 1 else ''})",
                "detail": f"MMCM calculation failures: {mmcm}. Timing-detector failures: {timing}.",
                "action": "Avoid 4K60/high-bandwidth output during testing. Use a fixed 1080p60 RGB 8-bit signal.",
            })
        if stream_down:
            findings.append({
                "severity": "warning",
                "title": f"Encoder input dropped {stream_down} time{'s' if stream_down != 1 else ''}",
                "detail": f"The input came up {stream_up} time(s), configured an active encoder {configuring} time(s), then dropped and deconfigured.",
                "action": "This points to the HDMI input/handshake before encoding, not necessarily the network stream itself.",
            })
        if hdcp:
            findings.append({
                "severity": "info",
                "title": f"HDCP was unauthenticated {hdcp} time{'s' if hdcp != 1 else ''}",
                "detail": "This may be normal for an unprotected desktop but matters for protected video services.",
                "action": "Test with the normal desktop first; do not use protected streaming content as the initial signal test.",
            })
        if not findings:
            findings.append({
                "severity": "info",
                "title": "No Q-SYS-specific critical pattern was detected",
                "detail": "Use the Events and Files views to search for device-specific messages.",
                "action": "Filter by Warning and Error, then search for the symptom you are investigating.",
            })
        self.findings = findings

    def _build_stats(self) -> None:
        severity_counts = {key: 0 for key in SEVERITY_ORDER}
        category_counts: dict[str, int] = {}
        sources: dict[str, int] = {}
        for event in self.events:
            severity_counts[event.severity] = severity_counts.get(event.severity, 0) + 1
            category_counts[event.category] = category_counts.get(event.category, 0) + 1
            sources[event.source] = sources.get(event.source, 0) + 1
        self.stats = {
            "total_events": len(self.events),
            "total_files": len(self.files),
            "text_files": sum(1 for f in self.files if f.text),
            "event_files": sum(1 for f in self.files if f.event_source),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "source_counts": sources,
            "resolutions": self._matching_resolutions(),
            "truncated": len(self.events) >= MAX_EVENTS,
        }

    # ------------------------------- API data -------------------------------

    def summary_payload(self) -> dict[str, Any]:
        return {
            "app_version": APP_VERSION,
            "metadata": self.metadata,
            "stats": self.stats,
            "findings": self.findings,
            "categories": sorted(self.stats["category_counts"]),
            "sources": sorted(self.stats["source_counts"]),
        }

    def filter_events(
        self,
        query: str,
        severity: str,
        category: str,
        source: str,
        page: int,
        page_size: int,
    ) -> dict[str, Any]:
        query_lower = query.strip().lower()
        wanted_severities = {s.strip() for s in severity.split(",") if s.strip()} if severity else set()
        filtered: list[Event] = []
        for event in self.events:
            if wanted_severities and event.severity not in wanted_severities:
                continue
            if category and event.category != category:
                continue
            if source and event.source != source:
                continue
            if query_lower and query_lower not in event.message.lower() and query_lower not in event.source.lower():
                continue
            filtered.append(event)

        total = len(filtered)
        page_size = max(25, min(page_size, 500))
        max_page = max(1, (total + page_size - 1) // page_size)
        page = max(1, min(page, max_page))
        start = (page - 1) * page_size
        rows = filtered[start:start + page_size]
        return {
            "events": [asdict(event) for event in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max_page,
        }

    def files_payload(self, query: str = "") -> dict[str, Any]:
        q = query.lower().strip()
        rows = [asdict(f) for f in self.files if not q or q in f.path.lower()]
        return {"files": rows, "total": len(rows)}

    def file_payload(self, rel: str, search: str = "") -> dict[str, Any]:
        safe = self._safe_archive_name(rel)
        if not safe:
            raise ValueError("Invalid file path.")
        path = (self.root / safe).resolve()
        root = self.root.resolve()
        if root not in path.parents and path != root:
            raise ValueError("Invalid file path.")
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(rel)
        info = next((item for item in self.files if item.path == safe.as_posix()), None)
        if not info or not info.text:
            return {"path": rel, "text": False, "content": "This is a binary file and cannot be shown as text."}
        content = self._read_text(path)
        if search:
            search_lower = search.lower()
            selected = []
            for number, line in enumerate(content.splitlines(), 1):
                if search_lower in line.lower():
                    selected.append(f"{number:>7}: {line}")
            content = "\n".join(selected) or "No matching lines."
        return {"path": rel, "text": True, "content": content}


# ---------------------------- HTTP / Web server -----------------------------


def json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def parse_multipart_file(content_type: str, body: bytes) -> tuple[str, bytes]:
    """Parse one multipart upload without relying on the deprecated cgi module."""
    match = re.search(r"boundary=(?:\"([^\"]+)\"|([^;]+))", content_type, re.I)
    if not match:
        raise ValueError("Missing multipart boundary.")
    boundary = (match.group(1) or match.group(2)).strip().encode("utf-8")
    delimiter = b"--" + boundary
    for part in body.split(delimiter):
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        header_blob, separator, data = part.partition(b"\r\n\r\n")
        if not separator:
            continue
        headers = header_blob.decode("utf-8", errors="replace")
        disposition = re.search(r"Content-Disposition:\s*form-data;[^\r\n]*name=\"file\"[^\r\n]*", headers, re.I)
        if not disposition:
            continue
        filename_match = re.search(r"filename=\"([^\"]*)\"", disposition.group(0), re.I)
        filename = Path(filename_match.group(1)).name if filename_match else "uploaded.qsyslog"
        data = data.rstrip(b"\r\n")
        return filename, data
    raise ValueError("No uploaded file was found.")


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = f"QsysDashboard/{APP_VERSION}"

    @property
    def app_state(self) -> DashboardState:
        return self.server.app_state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep the PyCharm console readable. Uncomment for HTTP request logs.
        return

    def _send(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: Any, status: int = 200) -> None:
        self._send(json_bytes(payload), "application/json; charset=utf-8", status)

    def _error(self, message: str, status: int = 400) -> None:
        self._json({"error": message}, status)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        try:
            if parsed.path == "/":
                self._send(DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            if parsed.path == "/api/status":
                with self.app_state.lock:
                    self._json({
                        "loaded": self.app_state.dataset is not None,
                        "error": self.app_state.last_error,
                        "name": self.app_state.dataset.source_path.name if self.app_state.dataset else None,
                    })
                return
            with self.app_state.lock:
                dataset = self.app_state.dataset
                if not dataset:
                    self._error("No log archive is loaded.", 404)
                    return
                if parsed.path == "/api/summary":
                    self._json(dataset.summary_payload())
                    return
                if parsed.path == "/api/events":
                    self._json(dataset.filter_events(
                        query=query.get("q", [""])[0],
                        severity=query.get("severity", [""])[0],
                        category=query.get("category", [""])[0],
                        source=query.get("source", [""])[0],
                        page=int(query.get("page", ["1"])[0]),
                        page_size=int(query.get("page_size", [str(DEFAULT_PAGE_SIZE)])[0]),
                    ))
                    return
                if parsed.path == "/api/files":
                    self._json(dataset.files_payload(query.get("q", [""])[0]))
                    return
                if parsed.path == "/api/file":
                    rel = query.get("path", [""])[0]
                    self._json(dataset.file_payload(rel, query.get("q", [""])[0]))
                    return
            self._error("Not found.", 404)
        except (ValueError, FileNotFoundError) as exc:
            self._error(str(exc), 400)
        except Exception as exc:  # pragma: no cover - last-resort diagnostics
            traceback.print_exc()
            self._error(f"Unexpected error: {exc}", 500)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/upload":
            self._error("Not found.", 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                raise ValueError("The upload was empty.")
            if length > MAX_UPLOAD_BYTES:
                raise ValueError("The upload is larger than the 250 MB safety limit.")
            body = self.rfile.read(length)
            filename, data = parse_multipart_file(self.headers.get("Content-Type", ""), body)
            upload_dir = Path(tempfile.mkdtemp(prefix="qsys-upload-"))
            upload_path = upload_dir / filename
            upload_path.write_bytes(data)
            try:
                dataset = QsysDataset(upload_path)
                # Keep the source inside the dataset temp folder so upload_dir can be removed.
                preserved = dataset.temp_dir / filename
                shutil.copy2(upload_path, preserved)
                dataset.source_path = preserved
                self.app_state.replace(dataset)
            finally:
                shutil.rmtree(upload_dir, ignore_errors=True)
            self._json({"ok": True, "name": filename})
        except Exception as exc:
            traceback.print_exc()
            self.app_state.set_error(str(exc))
            self._error(str(exc), 400)


class DashboardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], app_state: DashboardState):
        super().__init__(address, handler)
        self.app_state = app_state


# ---------------------------------- UI --------------------------------------

DASHBOARD_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Q-SYS Log Dashboard</title>
<style>
:root{--bg:#0b1020;--panel:#121a2e;--panel2:#18223a;--line:#273553;--text:#edf2ff;--muted:#9eacc8;--critical:#ff5f6d;--error:#ff9b54;--warning:#ffd166;--info:#59c3ff;--debug:#9b8cff;--good:#5ee6a8;--shadow:0 14px 36px rgba(0,0,0,.28)}
*{box-sizing:border-box} body{margin:0;background:linear-gradient(180deg,#0b1020 0%,#0e1425 100%);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh}
button,input,select{font:inherit}.app{display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100vh;padding:22px 16px;border-right:1px solid var(--line);background:rgba(9,14,28,.96)}
.brand{font-weight:850;font-size:19px;letter-spacing:-.02em;padding:8px 10px 22px}.brand small{display:block;color:var(--muted);font-size:11px;font-weight:600;margin-top:5px}.nav{display:grid;gap:7px}.nav button{background:transparent;border:1px solid transparent;color:var(--muted);text-align:left;padding:11px 12px;border-radius:10px;cursor:pointer}.nav button:hover,.nav button.active{background:var(--panel2);border-color:var(--line);color:var(--text)}
.sidebar-bottom{position:absolute;left:16px;right:16px;bottom:18px}.upload-label{display:block;text-align:center;padding:10px 12px;border-radius:10px;background:#285fe7;color:#fff;font-weight:750;cursor:pointer}.upload-label:hover{filter:brightness(1.08)}#fileInput{display:none}.privacy{font-size:11px;color:var(--muted);line-height:1.45;margin-top:12px}
.main{padding:28px 32px 56px;min-width:0}.header{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:22px}.header h1{margin:0 0 6px;font-size:28px;letter-spacing:-.035em}.header p{margin:0;color:var(--muted)}.status-pill{border:1px solid var(--line);background:var(--panel);padding:8px 11px;border-radius:999px;color:var(--muted);font-size:12px;white-space:nowrap}
.hidden{display:none!important}.empty{max-width:720px;margin:10vh auto;background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:38px;text-align:center;box-shadow:var(--shadow)}.empty h2{font-size:28px;margin:0 0 10px}.empty p{color:var(--muted);line-height:1.65}.dropzone{margin:26px 0 4px;border:1px dashed #5571a8;border-radius:14px;padding:34px;cursor:pointer;background:#101a31}.dropzone.drag{border-color:var(--info);background:#142744}.dropzone strong{display:block;margin-bottom:7px}.spinner{display:inline-block;width:15px;height:15px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite;vertical-align:-2px;margin-right:7px}@keyframes spin{to{transform:rotate(360deg)}}
.cards{display:grid;grid-template-columns:repeat(5,minmax(130px,1fr));gap:12px;margin-bottom:18px}.card{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:15px;min-width:0}.card .label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}.card .value{font-weight:830;font-size:19px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.card .sub{font-size:11px;color:var(--muted);margin-top:5px}.value.critical{color:var(--critical)}.value.warning{color:var(--warning)}.value.good{color:var(--good)}
.grid2{display:grid;grid-template-columns:1.25fr .75fr;gap:16px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:15px;overflow:hidden;box-shadow:0 5px 20px rgba(0,0,0,.13)}.panel-head{display:flex;align-items:center;justify-content:space-between;padding:16px 18px;border-bottom:1px solid var(--line)}.panel-head h2{font-size:15px;margin:0}.panel-body{padding:16px 18px}.finding{border:1px solid var(--line);border-left-width:4px;border-radius:10px;padding:13px 14px;margin-bottom:10px;background:#111a2d}.finding:last-child{margin-bottom:0}.finding.critical{border-left-color:var(--critical)}.finding.error{border-left-color:var(--error)}.finding.warning{border-left-color:var(--warning)}.finding.info{border-left-color:var(--info)}.finding-title{font-weight:780;margin-bottom:5px}.finding-detail,.finding-action{color:var(--muted);font-size:13px;line-height:1.5}.finding-action{margin-top:6px;color:#cbd7ef}.finding-action b{color:var(--text)}
.kv{display:grid;grid-template-columns:minmax(130px,1fr) minmax(100px,1fr);gap:0}.kv div{padding:9px 0;border-bottom:1px solid rgba(39,53,83,.7);font-size:13px}.kv div:nth-child(odd){color:var(--muted)}.bar-row{display:grid;grid-template-columns:90px 1fr 50px;align-items:center;gap:10px;margin:10px 0;font-size:12px}.bar-track{height:8px;background:#0b1222;border-radius:999px;overflow:hidden}.bar-fill{height:100%;background:linear-gradient(90deg,#3b82f6,#7c9cff);border-radius:999px}.bar-count{text-align:right;color:var(--muted)}
.toolbar{display:flex;gap:9px;flex-wrap:wrap;margin-bottom:13px}.toolbar input,.toolbar select{background:#0d1528;color:var(--text);border:1px solid var(--line);border-radius:9px;padding:9px 10px;outline:none}.toolbar input:focus,.toolbar select:focus{border-color:#4f78da}.toolbar input{min-width:280px;flex:1}.checks{display:flex;gap:6px;align-items:center;flex-wrap:wrap}.check{display:flex;align-items:center;gap:5px;border:1px solid var(--line);background:#0d1528;padding:7px 8px;border-radius:8px;font-size:12px;color:var(--muted)}.check input{min-width:auto;margin:0}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:11px;max-height:67vh}table{width:100%;border-collapse:collapse;font-size:12px}th{position:sticky;top:0;background:#18223a;text-align:left;padding:10px;border-bottom:1px solid var(--line);z-index:1;color:#c9d5ec}td{vertical-align:top;padding:9px 10px;border-bottom:1px solid rgba(39,53,83,.65)}tr:hover td{background:#151f35}.sev{font-weight:800;text-transform:uppercase;font-size:10px}.sev-critical{color:var(--critical)}.sev-error{color:var(--error)}.sev-warning{color:var(--warning)}.sev-info{color:var(--info)}.sev-debug{color:var(--debug)}.message{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word;line-height:1.45;min-width:520px}.source{color:var(--muted);white-space:nowrap}.pager{display:flex;align-items:center;justify-content:flex-end;gap:8px;margin-top:12px;color:var(--muted);font-size:12px}.pager button{border:1px solid var(--line);background:var(--panel2);color:var(--text);border-radius:8px;padding:7px 10px;cursor:pointer}.pager button:disabled{opacity:.35;cursor:not-allowed}
.file-layout{display:grid;grid-template-columns:340px minmax(0,1fr);gap:14px;height:72vh}.file-list,.viewer{border:1px solid var(--line);background:var(--panel);border-radius:12px;overflow:hidden}.file-search{padding:10px;border-bottom:1px solid var(--line)}.file-search input{width:100%;background:#0d1528;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px}.file-scroll{height:calc(72vh - 58px);overflow:auto}.file-row{padding:10px 12px;border-bottom:1px solid rgba(39,53,83,.65);cursor:pointer}.file-row:hover,.file-row.active{background:var(--panel2)}.file-name{font-size:12px;word-break:break-all}.file-meta{font-size:10px;color:var(--muted);margin-top:4px}.viewer-head{display:flex;gap:8px;align-items:center;padding:10px;border-bottom:1px solid var(--line)}.viewer-head input{flex:1;background:#0d1528;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:8px}.viewer-title{font-size:12px;color:var(--muted);max-width:45%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.viewer pre{margin:0;height:calc(72vh - 55px);overflow:auto;padding:14px;font:12px/1.48 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word;color:#d9e3f7;background:#0b1222}
.toast{position:fixed;right:22px;bottom:22px;max-width:420px;padding:12px 15px;border:1px solid var(--line);border-radius:11px;background:#17223a;box-shadow:var(--shadow);z-index:9}.toast.error{border-color:var(--critical)}
@media(max-width:1050px){.cards{grid-template-columns:repeat(2,1fr)}.grid2{grid-template-columns:1fr}.file-layout{grid-template-columns:280px minmax(0,1fr)}}
@media(max-width:760px){.app{display:block}.sidebar{position:static;height:auto;border-right:0;border-bottom:1px solid var(--line)}.sidebar-bottom{position:static;margin-top:14px}.nav{grid-template-columns:repeat(3,1fr)}.main{padding:22px 14px}.header{display:block}.status-pill{display:inline-block;margin-top:12px}.cards{grid-template-columns:1fr 1fr}.file-layout{grid-template-columns:1fr;height:auto}.file-scroll{height:260px}.viewer pre{height:55vh}.message{min-width:360px}}
</style>
</head>
<body>
<div class="app">
<aside class="sidebar">
  <div class="brand">Q-SYS Log Dashboard<small>Local diagnostic viewer</small></div>
  <nav class="nav">
    <button class="active" data-view="overview">Overview</button>
    <button data-view="events">Events</button>
    <button data-view="files">Files</button>
  </nav>
  <div class="sidebar-bottom">
    <label class="upload-label" for="fileInput">Open another log</label>
    <input id="fileInput" type="file" accept=".qsyslog,.zip,.gz,.tgz,.tar,.log,.txt">
    <div class="privacy">Runs only on 127.0.0.1. Log data stays on this computer.</div>
  </div>
</aside>
<main class="main">
  <section id="emptyView" class="empty hidden">
    <h2>Open a Q-SYS diagnostic log</h2>
    <p>Select a <b>.qsyslog</b>, ZIP, tar archive, or normal text log. The dashboard will extract it locally and identify Q-SYS HDMI, encoder, thermal, network, and design events.</p>
    <div id="dropzone" class="dropzone">
      <strong>Drop a log here</strong>
      <span>or click to choose a file</span>
    </div>
  </section>

  <div id="dashboard" class="hidden">
    <header class="header">
      <div><h1 id="pageTitle">Device overview</h1><p id="archiveName"></p></div>
      <div id="loadStatus" class="status-pill">Loaded</div>
    </header>

    <section id="overviewView" class="view">
      <div id="cards" class="cards"></div>
      <div class="grid2">
        <div class="panel"><div class="panel-head"><h2>Important findings</h2></div><div id="findings" class="panel-body"></div></div>
        <div class="panel"><div class="panel-head"><h2>Device details</h2></div><div id="deviceDetails" class="panel-body"></div></div>
      </div>
      <div class="grid2" style="margin-top:16px">
        <div class="panel"><div class="panel-head"><h2>Event categories</h2></div><div id="categoryBars" class="panel-body"></div></div>
        <div class="panel"><div class="panel-head"><h2>Encoder resolutions detected</h2></div><div id="resolutionList" class="panel-body"></div></div>
      </div>
    </section>

    <section id="eventsView" class="view hidden">
      <div class="toolbar">
        <input id="eventSearch" type="search" placeholder="Search messages and source files…">
        <select id="categoryFilter"><option value="">All categories</option></select>
        <select id="sourceFilter"><option value="">All log files</option></select>
      </div>
      <div class="toolbar checks">
        <label class="check"><input class="sevCheck" type="checkbox" value="critical" checked> Critical</label>
        <label class="check"><input class="sevCheck" type="checkbox" value="error" checked> Error</label>
        <label class="check"><input class="sevCheck" type="checkbox" value="warning" checked> Warning</label>
        <label class="check"><input class="sevCheck" type="checkbox" value="info"> Info</label>
        <label class="check"><input class="sevCheck" type="checkbox" value="debug"> Debug</label>
      </div>
      <div class="table-wrap"><table><thead><tr><th>Time</th><th>Level</th><th>Category</th><th>Source</th><th>Message</th></tr></thead><tbody id="eventRows"></tbody></table></div>
      <div class="pager"><span id="pageInfo"></span><button id="prevPage">Previous</button><button id="nextPage">Next</button></div>
    </section>

    <section id="filesView" class="view hidden">
      <div class="file-layout">
        <div class="file-list"><div class="file-search"><input id="fileSearch" type="search" placeholder="Filter files…"></div><div id="fileRows" class="file-scroll"></div></div>
        <div class="viewer"><div class="viewer-head"><span id="viewerTitle" class="viewer-title">Select a text file</span><input id="insideSearch" type="search" placeholder="Show only matching lines…"></div><pre id="fileContent">Select a file from the left.</pre></div>
      </div>
    </section>
  </div>
</main>
</div>
<div id="toast" class="toast hidden"></div>
<script>
const state={summary:null,page:1,pages:1,currentFile:"",uploading:false};
const $=s=>document.querySelector(s); const $$=s=>[...document.querySelectorAll(s)];
function esc(v){return String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function fmtNum(v){return Number(v||0).toLocaleString();}
function fmtBytes(n){if(n<1024)return n+" B";if(n<1048576)return(n/1024).toFixed(1)+" KB";return(n/1048576).toFixed(1)+" MB";}
function toast(message,error=false){const t=$("#toast");t.textContent=message;t.className="toast"+(error?" error":"");setTimeout(()=>t.classList.add("hidden"),5000);}
async function api(url,options){const r=await fetch(url,options);let data;try{data=await r.json()}catch{data={error:"Invalid server response"}}if(!r.ok)throw new Error(data.error||r.statusText);return data;}
function setUploading(on){state.uploading=on;$("#loadStatus").innerHTML=on?'<span class="spinner"></span>Reading log…':'Loaded';}
async function upload(file){if(!file||state.uploading)return;setUploading(true);const fd=new FormData();fd.append("file",file,file.name);try{await api("/api/upload",{method:"POST",body:fd});await loadDashboard();toast("Loaded "+file.name);}catch(e){toast(e.message,true);$("#emptyView").classList.remove("hidden");$("#dashboard").classList.add("hidden");}finally{setUploading(false);}}
async function init(){const status=await api("/api/status");if(status.loaded)await loadDashboard();else{$("#emptyView").classList.remove("hidden");$("#dashboard").classList.add("hidden");}}
async function loadDashboard(){state.summary=await api("/api/summary");$("#emptyView").classList.add("hidden");$("#dashboard").classList.remove("hidden");renderOverview();populateFilters();state.page=1;await loadEvents();await loadFiles();}
function val(v,fallback="Not found"){return v===null||v===undefined||v===""?fallback:v;}
function renderOverview(){const s=state.summary,m=s.metadata,c=s.stats.severity_counts;$("#archiveName").textContent=m.source_name;const status=String(m.design_status);const statusClass=/compromised|fault|stopped/i.test(status)?"critical":/warning/i.test(status)?"warning":"good";
const cards=[
 ["Device",m.hostname,"Firmware "+m.firmware,""],
 ["Design status",m.design_status,m.hdmi_input_1?"HDMI 1: "+m.hdmi_input_1:"",statusClass],
 ["Fan 1",m.fan_1_rpm+(/^[0-9]+$/.test(m.fan_1_rpm)?" RPM":""),m.fan_pwm_percent!==null&&m.fan_pwm_percent!==undefined?"Drive: "+m.fan_pwm_percent+"%":"",m.fan_1_rpm==="0"?"critical":""],
 ["Temperature",m.temperature_1_c!==null?m.temperature_1_c+"°C":"Not found",m.temperature_1_max_c!==null?"Alarm point: "+m.temperature_1_max_c+"°C":"",m.temperature_max_alarm?"critical":""],
 ["Errors / warnings",fmtNum((c.critical||0)+(c.error||0))+" / "+fmtNum(c.warning||0),fmtNum(s.stats.total_events)+" indexed events",(c.critical||c.error)?"warning":"good"]
];
$("#cards").innerHTML=cards.map(x=>`<div class="card"><div class="label">${esc(x[0])}</div><div class="value ${x[3]}">${esc(x[1])}</div><div class="sub">${esc(x[2])}</div></div>`).join("");
$("#findings").innerHTML=s.findings.map(f=>`<div class="finding ${esc(f.severity)}"><div class="finding-title">${esc(f.title)}</div><div class="finding-detail">${esc(f.detail)}</div><div class="finding-action"><b>Next step:</b> ${esc(f.action)}</div></div>`).join("");
const details=[["Source",m.source_name],["Hostname",m.hostname],["Serial number",m.serial],["Firmware",m.firmware],["Platform",m.platform],["IP address",m.ip_address],["HDMI input 1",m.hdmi_input_1],["Secondary temperature",m.temperature_2_c!==null?m.temperature_2_c+"°C":"Not found"],["Files",fmtNum(s.stats.total_files)],["Event log files",fmtNum(s.stats.event_files)]];
$("#deviceDetails").innerHTML='<div class="kv">'+details.map(r=>`<div>${esc(r[0])}</div><div>${esc(r[1])}</div>`).join("")+'</div>';
const cats=Object.entries(s.stats.category_counts).sort((a,b)=>b[1]-a[1]);const max=Math.max(1,...cats.map(x=>x[1]));$("#categoryBars").innerHTML=cats.map(([name,count])=>`<div class="bar-row"><span>${esc(name)}</span><div class="bar-track"><div class="bar-fill" style="width:${Math.max(2,count/max*100)}%"></div></div><span class="bar-count">${fmtNum(count)}</span></div>`).join("")||'<span style="color:var(--muted)">No events indexed.</span>';
$("#resolutionList").innerHTML=s.stats.resolutions.length?'<div class="kv">'+s.stats.resolutions.map(r=>`<div>${esc(r.resolution)}</div><div>${fmtNum(r.count)} encoder configuration event(s)</div>`).join("")+'</div>':'<span style="color:var(--muted)">No active encoder resolution was found.</span>';
}
function populateFilters(){const s=state.summary;$("#categoryFilter").innerHTML='<option value="">All categories</option>'+s.categories.map(v=>`<option>${esc(v)}</option>`).join("");$("#sourceFilter").innerHTML='<option value="">All log files</option>'+s.sources.map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join("");}
function selectedSeverities(){return $$(".sevCheck:checked").map(x=>x.value).join(",");}
async function loadEvents(){const p=new URLSearchParams({q:$("#eventSearch").value,severity:selectedSeverities(),category:$("#categoryFilter").value,source:$("#sourceFilter").value,page:String(state.page),page_size:"150"});const d=await api("/api/events?"+p);state.page=d.page;state.pages=d.pages;$("#eventRows").innerHTML=d.events.map(e=>`<tr><td>${esc(e.timestamp||"—")}</td><td><span class="sev sev-${esc(e.severity)}">${esc(e.severity)}</span></td><td>${esc(e.category)}</td><td class="source">${esc(e.source)}:${e.line_number}</td><td class="message">${esc(e.message)}</td></tr>`).join("")||'<tr><td colspan="5" style="padding:30px;text-align:center;color:var(--muted)">No matching events.</td></tr>';$("#pageInfo").textContent=`Page ${d.page} of ${d.pages} · ${fmtNum(d.total)} events`;$("#prevPage").disabled=d.page<=1;$("#nextPage").disabled=d.page>=d.pages;}
let eventTimer;function queueEvents(){clearTimeout(eventTimer);eventTimer=setTimeout(()=>{state.page=1;loadEvents().catch(e=>toast(e.message,true));},220);}
async function loadFiles(){const d=await api("/api/files?q="+encodeURIComponent($("#fileSearch").value));$("#fileRows").innerHTML=d.files.map(f=>`<div class="file-row ${f.path===state.currentFile?'active':''}" data-path="${esc(f.path)}"><div class="file-name">${esc(f.path)}</div><div class="file-meta">${esc(f.kind)} · ${fmtBytes(f.size)}${f.event_source?' · event source':''}</div></div>`).join("");$$(".file-row").forEach(row=>row.onclick=()=>openFile(row.dataset.path));}
async function openFile(path){state.currentFile=path;$("#viewerTitle").textContent=path;await loadFiles();await loadFileContent();}
async function loadFileContent(){if(!state.currentFile)return;const p=new URLSearchParams({path:state.currentFile,q:$("#insideSearch").value});const d=await api("/api/file?"+p);$("#fileContent").textContent=d.content;}
let fileTimer;$("#fileSearch").addEventListener("input",()=>{clearTimeout(fileTimer);fileTimer=setTimeout(()=>loadFiles().catch(e=>toast(e.message,true)),180)});$("#insideSearch").addEventListener("input",()=>{clearTimeout(fileTimer);fileTimer=setTimeout(()=>loadFileContent().catch(e=>toast(e.message,true)),220)});
$$('.nav button').forEach(btn=>btn.onclick=()=>{$$('.nav button').forEach(x=>x.classList.toggle('active',x===btn));$$('.view').forEach(x=>x.classList.add('hidden'));$('#'+btn.dataset.view+'View').classList.remove('hidden');const titles={overview:'Device overview',events:'Log events',files:'Archive files'};$('#pageTitle').textContent=titles[btn.dataset.view];});
$("#eventSearch").addEventListener("input",queueEvents);$("#categoryFilter").addEventListener("change",queueEvents);$("#sourceFilter").addEventListener("change",queueEvents);$$('.sevCheck').forEach(x=>x.addEventListener('change',queueEvents));$("#prevPage").onclick=()=>{if(state.page>1){state.page--;loadEvents()}};$("#nextPage").onclick=()=>{if(state.page<state.pages){state.page++;loadEvents()}};
const input=$("#fileInput");input.addEventListener("change",()=>{if(input.files[0])upload(input.files[0]);input.value=""});const dz=$("#dropzone");dz.onclick=()=>input.click();['dragenter','dragover'].forEach(e=>dz.addEventListener(e,ev=>{ev.preventDefault();dz.classList.add('drag')}));['dragleave','drop'].forEach(e=>dz.addEventListener(e,ev=>{ev.preventDefault();dz.classList.remove('drag')}));dz.addEventListener('drop',ev=>upload(ev.dataTransfer.files[0]));
init().catch(e=>toast(e.message,true));
</script>
</body>
</html>'''


def choose_file_gui() -> Optional[Path]:
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected = filedialog.askopenfilename(
            title="Open a Q-SYS diagnostic log",
            filetypes=[
                ("Q-SYS logs", "*.qsyslog"),
                ("Archives", "*.zip *.gz *.tgz *.tar"),
                ("Text logs", "*.log *.txt"),
                ("All files", "*.*"),
            ],
        )
        root.destroy()
        return Path(selected) if selected else None
    except Exception:
        return None


def find_open_port(host: str, requested: int) -> int:
    if requested:
        return requested
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Open a local dashboard for Q-SYS diagnostic logs.")
    parser.add_argument("log", nargs="?", help="Optional .qsyslog, archive, directory, or text log to open.")
    parser.add_argument("--host", default="127.0.0.1", help="Listening address. Default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=0, help="Listening port. Default: choose a free port")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically.")
    parser.add_argument("--no-picker", action="store_true", help="Do not show a file picker when no path is supplied.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    state = DashboardState()
    source: Optional[Path] = Path(args.log).expanduser().resolve() if args.log else None
    if not source and not args.no_picker:
        source = choose_file_gui()
    if source:
        if not source.exists():
            print(f"File not found: {source}")
            return 2
        try:
            print(f"Reading {source.name} …")
            state.replace(QsysDataset(source))
            print(f"Indexed {len(state.dataset.events):,} events from {len(state.dataset.files):,} files.")
        except Exception as exc:
            state.set_error(str(exc))
            print(f"Could not read the log: {exc}")
            traceback.print_exc()

    port = find_open_port(args.host, args.port)
    server = DashboardHTTPServer((args.host, port), DashboardHandler, state)
    url = f"http://{args.host}:{port}"
    print(f"\n{APP_NAME} {APP_VERSION}")
    print(f"Dashboard: {url}")
    print("Press Ctrl+C to stop. Log data remains on this computer.\n")
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nStopping dashboard …")
    finally:
        server.shutdown()
        server.server_close()
        with state.lock:
            if state.dataset:
                state.dataset.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
