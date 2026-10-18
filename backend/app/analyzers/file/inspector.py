import io
import os
import re
import zipfile
import email
from email import policy
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from app.analyzers.file.validator import ValidatedFile


@dataclass
class FileInspectionFinding:
    indicator_type: str
    description: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence: float
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileInspectionResult:
    detected_format: str
    is_executable: bool
    findings: List[FileInspectionFinding]
    extracted_urls: List[str]
    metadata: Dict[str, Any]
    summary_text: str


class FileInspector:
    """Safe, non-executing static inspector for untrusted file uploads:
    - PDF: Searches for /JavaScript, /Launch, /OpenAction, /URI, embedded files
    - Office OpenXML: Searches for VBA macros, template injection, auto-run events
    - EML: Parses headers, sender mismatch, attachment extensions, body links
    - ZIP: Detects zip-slips, nested executables, high compression ratios
    - Scripts/Text: Detects LOLBins, encoded commands, download cradles
    - Executables: Truthfully declares static analysis limitation and flags binary risk
    """

    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
        ".wsf", ".hta", ".cpl", ".jar", ".iso", ".img", ".lnk", ".pif",
    }

    VBA_AUTO_EXEC = [
        r"autoopen", r"document_open", r"workbook_open", r"auto_open",
        r"autoexec", r"document_close", r"autoexit"
    ]

    VBA_DANGEROUS_CALLS = [
        r"shell\b", r"wscript\.shell", r"powershell", r"cmd\.exe",
        r"urldownloadtofile", r"msxml2\.xmlhttp", r"winhttprequest",
        r"createobject\(", r"environ\("
    ]

    SCRIPT_DANGEROUS_PATTERNS = [
        (r"(?i)\bpowershell(\.exe)?\b.*(-e|-enc|-encodedcommand)\b", "Encoded PowerShell Execution", "CRITICAL"),
        (r"(?i)\b(invoke-expression|iex)\b", "PowerShell Dynamic Code Execution (IEX)", "HIGH"),
        (r"(?i)\bdownloadstring\b|\bdownloaddata\b|\bdownloadfile\b", "Web Download Cradle", "HIGH"),
        (r"(?i)\bcertutil(\.exe)?\s+(-urlcache|-decode|-f)\b", "Certutil Living-off-the-Land Binary (LOLBin) Abuse", "HIGH"),
        (r"(?i)\bbitsadmin(\.exe)?\s+/transfer\b", "Bitsadmin File Transfer Abuse", "HIGH"),
        (r"(?i)\bmshta(\.exe)?\b", "MSHTA Proxy Execution", "HIGH"),
        (r"(?i)\bregsvr32(\.exe)?\s+.*(/s\s+)?(/u\s+)?/i:\b", "Regsvr32 Squiblydoo Proxy Execution", "CRITICAL"),
        (r"(?i)\bcmd(\.exe)?\s+/c\b", "Command Prompt Subshell Spawn", "MEDIUM"),
        (r"(?i)\b(eval|exec)\s*\(", "Dynamic Code Evaluation", "MEDIUM"),
    ]

    URL_REGEX = re.compile(
        r"https?://[a-zA-Z0-9\.\-\_\~:\?#\[\]@!\$&'\(\)\*\+,;=%/]+",
        re.IGNORECASE
    )

    @classmethod
    def inspect(cls, validated_file: ValidatedFile) -> FileInspectionResult:
        """Runs the appropriate safe static inspector based on detected format."""
        fmt = validated_file.detected_format
        findings: List[FileInspectionFinding] = []
        extracted_urls: List[str] = []
        metadata: Dict[str, Any] = {
            "file_size": validated_file.file_size_bytes,
            "detected_format": fmt,
            "safe_extension": validated_file.safe_extension,
            "mime_type": validated_file.mime_type,
            "sha256": validated_file.sha256_hash,
            "sha1": validated_file.sha1_hash,
            "md5": validated_file.md5_hash,
        }

        if validated_file.is_executable:
            cls._inspect_executable(validated_file, findings, metadata)
        elif fmt == "pdf":
            cls._inspect_pdf(validated_file.content, findings, extracted_urls, metadata)
        elif fmt in ("docx", "docm", "xlsx", "xlsm", "pptx", "pptm"):
            cls._inspect_office(validated_file.content, fmt, findings, extracted_urls, metadata)
        elif fmt == "zip":
            cls._inspect_zip(validated_file.content, findings, metadata)
        elif fmt == "eml":
            cls._inspect_eml(validated_file.content, findings, extracted_urls, metadata)
        elif fmt == "text":
            cls._inspect_text(validated_file.content, findings, extracted_urls, metadata)
        else:
            findings.append(FileInspectionFinding(
                indicator_type="UNRECOGNIZED_BINARY_FORMAT",
                description="File is an opaque binary stream not matching standard document or archive profiles.",
                severity="LOW",
                confidence=0.5,
                evidence={"mime": validated_file.mime_type}
            ))

        # Build human-readable summary
        summary = cls._generate_summary(validated_file, findings)

        return FileInspectionResult(
            detected_format=fmt,
            is_executable=validated_file.is_executable,
            findings=findings,
            extracted_urls=list(set(extracted_urls))[:20],
            metadata=metadata,
            summary_text=summary,
        )

    @classmethod
    def _inspect_executable(
        cls,
        vfile: ValidatedFile,
        findings: List[FileInspectionFinding],
        metadata: Dict[str, Any],
    ) -> None:
        metadata["execution_status"] = "UNSUPPORTED_SAFE_BY_DESIGN"
        metadata["disclaimer"] = (
            "XEROX enforces strict defensive containment. Untrusted binary files (PE/ELF/Mach-O) "
            "are not dynamically executed or sandboxed to prevent guest escape vulnerabilities. "
            "Static signature and cryptographic hash intelligence lookup are applied."
        )
        findings.append(FileInspectionFinding(
            indicator_type="EXECUTABLE_BINARY_DETECTED",
            description=(
                f"Binary executable file signature detected ({vfile.client_filename}). "
                "Direct execution is disabled for platform safety. Cryptographic hash intelligence lookup applied."
            ),
            severity="HIGH",
            confidence=0.99,
            evidence={
                "client_filename": vfile.client_filename,
                "mime_type": vfile.mime_type,
                "sha256": vfile.sha256_hash,
            }
        ))

    @classmethod
    def _inspect_pdf(
        cls,
        content: bytes,
        findings: List[FileInspectionFinding],
        extracted_urls: List[str],
        metadata: Dict[str, Any],
    ) -> None:
        # Search for PDF action tags
        text = content.decode("latin-1", errors="ignore")
        metadata["pdf_version"] = text[:10].strip()

        # Dangerous PDF keywords
        if "/JavaScript" in text or "/JS" in text:
            findings.append(FileInspectionFinding(
                indicator_type="PDF_EMBEDDED_JAVASCRIPT",
                description="PDF contains embedded JavaScript (/JavaScript or /JS object). Often abused for client-side exploits.",
                severity="HIGH",
                confidence=0.90,
                evidence={"keyword": "/JavaScript"}
            ))

        if "/Launch" in text:
            findings.append(FileInspectionFinding(
                indicator_type="PDF_LAUNCH_ACTION",
                description="PDF contains a /Launch action capable of executing external operating system applications.",
                severity="CRITICAL",
                confidence=0.95,
                evidence={"keyword": "/Launch"}
            ))

        if "/OpenAction" in text or "/AA" in text:
            findings.append(FileInspectionFinding(
                indicator_type="PDF_AUTO_ACTION",
                description="PDF contains automatic action triggers (/OpenAction or /AA) that execute without explicit user action.",
                severity="MEDIUM",
                confidence=0.80,
                evidence={"keywords": ["/OpenAction", "/AA"]}
            ))

        if "/EmbeddedFiles" in text:
            findings.append(FileInspectionFinding(
                indicator_type="PDF_EMBEDDED_FILES",
                description="PDF contains embedded file streams (/EmbeddedFiles) which may conceal malicious secondary payloads.",
                severity="MEDIUM",
                confidence=0.75,
                evidence={"keyword": "/EmbeddedFiles"}
            ))

        # Extract URLs
        uris = re.findall(r"/URI\s*\((https?://[^)]+)\)", text, re.IGNORECASE)
        for u in uris:
            extracted_urls.append(u.strip())

        # Also generic URL regex on PDF content
        for match in cls.URL_REGEX.finditer(text):
            url_str = match.group(0)
            if len(url_str) < 256:
                extracted_urls.append(url_str)

        metadata["extracted_url_count"] = len(extracted_urls)

    @classmethod
    def _inspect_office(
        cls,
        content: bytes,
        fmt: str,
        findings: List[FileInspectionFinding],
        extracted_urls: List[str],
        metadata: Dict[str, Any],
    ) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                namelist = zf.namelist()
                metadata["zip_entry_count"] = len(namelist)

                # Check for VBA project
                has_vba = any("vbaProject.bin" in name for name in namelist)
                metadata["has_vba_macros"] = has_vba

                if has_vba:
                    findings.append(FileInspectionFinding(
                        indicator_type="OFFICE_VBA_MACRO_PRESENT",
                        description=f"Office document ({fmt}) contains embedded VBA macros (vbaProject.bin).",
                        severity="HIGH",
                        confidence=0.95,
                        evidence={"entry": "vbaProject.bin"}
                    ))
                    # Scan vbaProject.bin bytes for auto-exec and dangerous functions
                    for name in namelist:
                        if "vbaProject.bin" in name:
                            try:
                                vba_bytes = zf.read(name)
                                vba_text = vba_bytes.decode("latin-1", errors="ignore").lower()
                                
                                auto_execs = [ae for ae in cls.VBA_AUTO_EXEC if re.search(ae, vba_text)]
                                if auto_execs:
                                    findings.append(FileInspectionFinding(
                                        indicator_type="OFFICE_VBA_AUTO_EXEC",
                                        description=f"VBA macro contains automatic execution routines: {', '.join(auto_execs)}.",
                                        severity="HIGH",
                                        confidence=0.92,
                                        evidence={"auto_exec_routines": auto_execs}
                                    ))

                                dangerous_calls = [dc for dc in cls.VBA_DANGEROUS_CALLS if re.search(dc, vba_text)]
                                if dangerous_calls:
                                    findings.append(FileInspectionFinding(
                                        indicator_type="OFFICE_VBA_DANGEROUS_CALL",
                                        description=f"VBA macro contains suspicious system calls: {', '.join(dangerous_calls)}.",
                                        severity="CRITICAL",
                                        confidence=0.95,
                                        evidence={"suspicious_calls": dangerous_calls}
                                    ))
                            except Exception:
                                pass

                # Check for External Relationships (Template Injection)
                for name in namelist:
                    if name.endswith(".rels"):
                        try:
                            rel_data = zf.read(name).decode("utf-8", errors="ignore")
                            # Check TargetMode="External"
                            for rel_match in re.finditer(r'Target="([^"]+)"\s+TargetMode="External"', rel_data, re.IGNORECASE):
                                target = rel_match.group(1)
                                extracted_urls.append(target)
                                if target.startswith("http") and ("dotm" in target or "template" in target):
                                    findings.append(FileInspectionFinding(
                                        indicator_type="OFFICE_TEMPLATE_INJECTION",
                                        description=f"Remote template injection reference identified: {target}.",
                                        severity="CRITICAL",
                                        confidence=0.95,
                                        evidence={"target": target, "rel_file": name}
                                    ))
                        except Exception:
                            pass
        except Exception as e:
            findings.append(FileInspectionFinding(
                indicator_type="MALFORMED_OFFICE_CONTAINER",
                description=f"Unable to parse Office OpenXML package: {str(e)}.",
                severity="LOW",
                confidence=0.6,
                evidence={"error": str(e)}
            ))

    @classmethod
    def _inspect_zip(
        cls,
        content: bytes,
        findings: List[FileInspectionFinding],
        metadata: Dict[str, Any],
    ) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                entries = zf.infolist()
                metadata["zip_entry_count"] = len(entries)
                total_uncompressed = sum(e.file_size for e in entries)
                metadata["total_uncompressed_bytes"] = total_uncompressed

                # Zip bomb check
                compressed_size = len(content)
                if compressed_size > 0 and (total_uncompressed / compressed_size) > 100 and total_uncompressed > 50 * 1024 * 1024:
                    findings.append(FileInspectionFinding(
                        indicator_type="ZIP_BOMB_ANOMALY",
                        description=f"Extreme compression ratio ({total_uncompressed / compressed_size:.1f}x) indicative of decompression bomb.",
                        severity="CRITICAL",
                        confidence=0.95,
                        evidence={"ratio": total_uncompressed / compressed_size}
                    ))

                # Zip slip / directory traversal in member names
                for e in entries:
                    if ".." in e.filename or e.filename.startswith(("/", "\\")):
                        findings.append(FileInspectionFinding(
                            indicator_type="ZIP_SLIP_PATH_TRAVERSAL",
                            description=f"Archive contains path-traversal entry ('{e.filename}') targeting arbitrary filesystem write.",
                            severity="CRITICAL",
                            confidence=0.98,
                            evidence={"entry": e.filename}
                        ))

                    # Check extension
                    _, ext = os.path.splitext(e.filename.lower())
                    if ext in cls.SUSPICIOUS_EXTENSIONS:
                        findings.append(FileInspectionFinding(
                            indicator_type="ZIP_NESTED_EXECUTABLE",
                            description=f"Archive contains high-risk executable entry: '{e.filename}'.",
                            severity="HIGH",
                            confidence=0.90,
                            evidence={"entry": e.filename, "extension": ext}
                        ))
        except Exception as e:
            findings.append(FileInspectionFinding(
                indicator_type="MALFORMED_ZIP_ARCHIVE",
                description=f"Corrupted or malformed archive header: {str(e)}.",
                severity="LOW",
                confidence=0.6,
                evidence={"error": str(e)}
            ))

    @classmethod
    def _inspect_eml(
        cls,
        content: bytes,
        findings: List[FileInspectionFinding],
        extracted_urls: List[str],
        metadata: Dict[str, Any],
    ) -> None:
        try:
            msg = email.message_from_bytes(content, policy=policy.default)
            sender = msg.get("from", "")
            reply_to = msg.get("reply-to", "")
            subject = msg.get("subject", "")
            date = msg.get("date", "")

            metadata["sender"] = sender
            metadata["reply_to"] = reply_to
            metadata["subject"] = subject
            metadata["date"] = date

            # Sender mismatch check
            if reply_to and sender:
                clean_from = re.findall(r"[\w\.-]+@[\w\.-]+", sender)
                clean_reply = re.findall(r"[\w\.-]+@[\w\.-]+", reply_to)
                if clean_from and clean_reply and clean_from[0].lower() != clean_reply[0].lower():
                    findings.append(FileInspectionFinding(
                        indicator_type="EMAIL_REPLY_TO_MISMATCH",
                        description=f"From address ({clean_from[0]}) does not match Reply-To address ({clean_reply[0]}).",
                        severity="MEDIUM",
                        confidence=0.85,
                        evidence={"from": clean_from[0], "reply_to": clean_reply[0]}
                    ))

            # Inspect parts
            for part in msg.walk():
                ctype = part.get_content_type()
                filename = part.get_filename()

                if filename:
                    _, ext = os.path.splitext(filename.lower())
                    if ext in cls.SUSPICIOUS_EXTENSIONS:
                        findings.append(FileInspectionFinding(
                            indicator_type="EMAIL_DANGEROUS_ATTACHMENT",
                            description=f"Email contains high-risk attachment filename: '{filename}'.",
                            severity="HIGH",
                            confidence=0.95,
                            evidence={"attachment": filename, "extension": ext}
                        ))

                if ctype in ("text/plain", "text/html"):
                    try:
                        body = part.get_content()
                        if isinstance(body, str):
                            for match in cls.URL_REGEX.finditer(body):
                                extracted_urls.append(match.group(0))
                    except Exception:
                        pass
        except Exception as e:
            findings.append(FileInspectionFinding(
                indicator_type="MALFORMED_EML_MESSAGE",
                description=f"Failed to parse RFC 822 email: {str(e)}.",
                severity="LOW",
                confidence=0.5,
                evidence={"error": str(e)}
            ))

    @classmethod
    def _inspect_text(
        cls,
        content: bytes,
        findings: List[FileInspectionFinding],
        extracted_urls: List[str],
        metadata: Dict[str, Any],
    ) -> None:
        text = content.decode("utf-8", errors="ignore")
        metadata["text_length"] = len(text)

        # Check script patterns
        for pattern, desc, sev in cls.SCRIPT_DANGEROUS_PATTERNS:
            if re.search(pattern, text):
                findings.append(FileInspectionFinding(
                    indicator_type="SUSPICIOUS_SCRIPT_PATTERN",
                    description=desc,
                    severity=sev,
                    confidence=0.85,
                    evidence={"pattern": desc}
                ))

        # Extract URLs
        for match in cls.URL_REGEX.finditer(text):
            extracted_urls.append(match.group(0))

    @classmethod
    def _generate_summary(cls, vfile: ValidatedFile, findings: List[FileInspectionFinding]) -> str:
        if not findings:
            return f"Static inspection of {vfile.client_filename} ({vfile.detected_format.upper()}) completed. No suspicious structural indicators detected."
        high_critical = [f for f in findings if f.severity in ("HIGH", "CRITICAL")]
        if high_critical:
            reasons = "; ".join(f.description for f in high_critical[:3])
            return f"Caution: Static inspection detected high-risk indicators in {vfile.client_filename}: {reasons}."
        reasons = "; ".join(f.description for f in findings[:2])
        return f"Static inspection noted low/medium severity patterns in {vfile.client_filename}: {reasons}."
