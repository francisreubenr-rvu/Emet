from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET

from normalizer.cvss_normalizer import normalize_cvss
from normalizer.unified_schema import ScannerRunState, Severity, UnifiedFinding, VerificationStatus
from scanners.scanner_base import ScannerAvailabilityResult, ScannerBase, ScannerExecutionResult


class NmapRunner(ScannerBase):
    name = "nmap"
    version = "phase1"

    _PROFILE_FLAGS = {
        "quick": ["-T4", "-F", "-Pn"],
        "standard": ["-sV", "-Pn"],
        "deep": ["-sV", "-sC", "-O", "-Pn"],
    }

    async def scan(self, *, target: str, profile: str, scan_id: str) -> ScannerExecutionResult:
        started = datetime.utcnow()
        availability = await self.is_available()
        if not availability.available:
            return ScannerExecutionResult(
                scanner=self.name,
                status=ScannerRunState.UNAVAILABLE,
                error=availability.reason,
                started_at=started,
                completed_at=datetime.utcnow(),
            )

        flags = self._PROFILE_FLAGS.get(profile.lower(), self._PROFILE_FLAGS["standard"])
        command = ["nmap", "-oX", "-", *flags, target]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        completed = datetime.utcnow()

        xml_output = stdout.decode("utf-8", errors="ignore")
        artifact_path = self._write_artifact(scan_id=scan_id, payload=xml_output)

        if process.returncode != 0:
            return ScannerExecutionResult(
                scanner=self.name,
                status=ScannerRunState.FAILED,
                findings=[],
                error=(stderr.decode("utf-8", errors="ignore") or "nmap command failed")[:1200],
                artifact_path=artifact_path,
                started_at=started,
                completed_at=completed,
            )

        findings = self.normalize({"xml": xml_output, "target": target, "scan_id": scan_id, "artifact_path": artifact_path})
        return ScannerExecutionResult(
            scanner=self.name,
            status=ScannerRunState.SUCCESS,
            findings=findings,
            artifact_path=artifact_path,
            started_at=started,
            completed_at=completed,
        )

    async def is_available(self) -> ScannerAvailabilityResult:
        if shutil.which("nmap") is None:
            return ScannerAvailabilityResult(scanner=self.name, available=False, reason="nmap binary not found")
        return ScannerAvailabilityResult(scanner=self.name, available=True)

    def normalize(self, raw_output: dict) -> list[UnifiedFinding]:
        xml_output = raw_output.get("xml", "")
        target = raw_output.get("target", "unknown")
        scan_id = raw_output.get("scan_id", "scan-unknown")
        artifact_path = raw_output.get("artifact_path", "")

        if not xml_output.strip():
            return []

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return []

        findings: list[UnifiedFinding] = []
        for host in root.findall("host"):
            addr = host.find("address")
            host_target = (addr.attrib.get("addr") if addr is not None else None) or target
            ports = host.find("ports")
            if ports is None:
                continue

            for port in ports.findall("port"):
                state = port.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue
                service_node = port.find("service")
                service_name = service_node.attrib.get("name", "unknown") if service_node is not None else "unknown"
                version = service_node.attrib.get("version", "") if service_node is not None else ""
                product = service_node.attrib.get("product", "") if service_node is not None else ""
                port_id = int(port.attrib.get("portid", "0") or 0)
                protocol = port.attrib.get("protocol", "tcp")

                cve_id, cvss, vector, title, remediation, refs = self._map_service_to_cve(service_name, product, version)
                score, vector_norm, severity = normalize_cvss(cvss, vector)
                verification = VerificationStatus.VERIFIED if cve_id else VerificationStatus.UNVERIFIED

                findings.append(
                    UnifiedFinding(
                        scan_id=scan_id,
                        target=host_target,
                        scanner_source=self.name,
                        title=title,
                        description=f"Open {protocol} port {port_id} detected for {service_name} {version}".strip(),
                        severity=severity,
                        cvss_score=score,
                        cvss_vector=vector_norm,
                        cve_id=cve_id,
                        affected_component=f"{service_name} {product}".strip() or service_name,
                        affected_version=version or None,
                        port=port_id if port_id > 0 else None,
                        protocol=protocol,
                        service=service_name,
                        evidence={"state": "open", "service": service_name, "product": product, "version": version},
                        remediation=remediation,
                        references=refs,
                        verification_status=verification,
                        confidence_score=76.0 if cve_id else 45.0,
                        false_positive_probability=0.22 if cve_id else 0.55,
                        tags=["network-scan", "service-discovery"],
                        source_artifact_path=artifact_path,
                    )
                )
        return findings

    def _map_service_to_cve(
        self,
        service_name: str,
        product: str,
        version: str,
    ) -> tuple[str | None, float, str, str, str, list[str]]:
        normalized = f"{service_name} {product}".lower()
        if "apache" in normalized or "activemq" in normalized:
            return (
                "CVE-2023-46604",
                8.8,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "Potential Apache ActiveMQ RCE exposure",
                "Upgrade ActiveMQ and restrict broker interface exposure.",
                ["https://nvd.nist.gov/vuln/detail/CVE-2023-46604"],
            )
        if "openssh" in normalized and version.startswith("7"):
            return (
                "CVE-2018-15473",
                5.3,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "OpenSSH username enumeration exposure",
                "Upgrade OpenSSH and enforce throttling.",
                ["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
            )
        return (
            None,
            0.0,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "Open service requires manual validation",
            "Review exposed service and harden access policy.",
            [],
        )

    def _write_artifact(self, *, scan_id: str, payload: str) -> str:
        base = Path("artifacts") / scan_id
        base.mkdir(parents=True, exist_ok=True)
        path = base / "nmap.xml"
        path.write_text(payload or "", encoding="utf-8")
        return str(path)
