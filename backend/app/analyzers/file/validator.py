import hashlib
import io
import os
import re
import zipfile
from dataclasses import dataclass
from typing import Optional, Tuple

from app.core.config import settings


class FileValidationError(ValueError):
    """Raised when an uploaded file fails validation checks."""
    pass


@dataclass(frozen=True)
class ValidatedFile:
    """Result of successful file upload validation."""
    content: bytes
    sha256_hash: str
    sha1_hash: str
    md5_hash: str
    file_size_bytes: int
    detected_format: str
    mime_type: str
    safe_extension: str
    client_filename: str
    is_executable: bool


class FileValidator:
    """Validates untrusted file uploads against strict defensive security constraints:
    - Maximum file size (15 MB) & zero-byte rejection
    - Magic-byte verification and structural format identification
    - Safe extension normalization
    - Executable binary detection (truthfully handled as static-analysis-only or unsupported execution)
    - Path traversal and filename sanitization
    - Multi-algorithm cryptographic hash generation (SHA-256, SHA-1, MD5)
    """

    MAGIC_PDF = b"%PDF-"
    MAGIC_ZIP = b"PK\x03\x04"
    MAGIC_ZIP_EMPTY = b"PK\x05\x06"
    MAGIC_ZIP_SPANNED = b"PK\x07\x08"
    MAGIC_WINDOWS_PE = b"MZ"
    MAGIC_ELF = b"\x7fELF"
    MAGIC_MACHO_32 = b"\xfe\xed\xfa\xce"
    MAGIC_MACHO_64 = b"\xfe\xed\xfa\xcf"
    MAGIC_MACHO_32_REV = b"\xce\xfa\xed\xfe"
    MAGIC_MACHO_64_REV = b"\xcf\xfa\xed\xfe"

    @classmethod
    def validate(
        cls,
        file_bytes: bytes,
        declared_mime: Optional[str] = None,
        client_filename: Optional[str] = None,
    ) -> ValidatedFile:
        """Validates file bytes, inspects magic signatures, sanitizes metadata, and hashes."""
        file_size = len(file_bytes)

        # 1. Size Constraints
        if file_size == 0:
            raise FileValidationError("Uploaded file is empty (0 bytes).")
        if file_size > settings.MAX_FILE_SIZE_BYTES:
            max_mb = settings.MAX_FILE_SIZE_BYTES / (1024 * 1024)
            raise FileValidationError(f"File size exceeds maximum allowed limit of {max_mb:.0f} MB.")

        # 2. Sanitize client-provided filename
        safe_client_name = "upload"
        client_ext = ""
        if client_filename:
            base = os.path.basename(client_filename).replace("\x00", "").strip()
            if base:
                safe_client_name = re.sub(r"[^\w\.\-\_]", "_", base)[:128]
                _, ext = os.path.splitext(safe_client_name)
                client_ext = ext.lower()

        # 3. Detect format via Magic Bytes & Structure
        detected_format, safe_ext, mime_type, is_executable = cls._detect_format(
            file_bytes, client_ext, declared_mime
        )

        # 4. Compute Cryptographic Hashes
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        sha1 = hashlib.sha1(file_bytes).hexdigest()
        md5 = hashlib.md5(file_bytes).hexdigest()

        return ValidatedFile(
            content=file_bytes,
            sha256_hash=sha256,
            sha1_hash=sha1,
            md5_hash=md5,
            file_size_bytes=file_size,
            detected_format=detected_format,
            mime_type=mime_type,
            safe_extension=safe_ext,
            client_filename=safe_client_name,
            is_executable=is_executable,
        )

    @classmethod
    def _detect_format(
        cls,
        data: bytes,
        client_ext: str,
        declared_mime: Optional[str],
    ) -> Tuple[str, str, str, bool]:
        """Inspects magic bytes and headers. Returns (format, safe_ext, mime_type, is_executable)."""
        header = data[:1024]

        # Check Executables (Windows PE, Linux ELF, macOS Mach-O)
        if header.startswith(cls.MAGIC_WINDOWS_PE):
            return "executable", ".exe", "application/x-dosexec", True
        if header.startswith(cls.MAGIC_ELF):
            return "executable", ".bin", "application/x-executable", True
        if header.startswith((cls.MAGIC_MACHO_32, cls.MAGIC_MACHO_64, cls.MAGIC_MACHO_32_REV, cls.MAGIC_MACHO_64_REV)):
            return "executable", ".bin", "application/x-mach-binary", True

        # Check PDF
        if header.startswith(cls.MAGIC_PDF):
            return "pdf", ".pdf", "application/pdf", False

        # Check ZIP / Office Open XML (DOCX, DOCM, XLSX, etc.)
        if header.startswith((cls.MAGIC_ZIP, cls.MAGIC_ZIP_EMPTY, cls.MAGIC_ZIP_SPANNED)):
            return cls._inspect_zip_archive(data, client_ext)

        # Check Email (EML / RFC 822)
        if cls._looks_like_eml(header):
            return "eml", ".eml", "message/rfc822", False

        # Check Text / Script
        if cls._looks_like_text(data[:4096]):
            ext = client_ext if client_ext in [".txt", ".csv", ".json", ".xml", ".ps1", ".bat", ".sh", ".py", ".js"] else ".txt"
            return "text", ext, "text/plain", False

        # Fallback to binary/unknown
        safe_ext = client_ext if client_ext and len(client_ext) <= 8 else ".bin"
        return "unknown", safe_ext, declared_mime or "application/octet-stream", False

    @classmethod
    def _inspect_zip_archive(cls, data: bytes, client_ext: str) -> Tuple[str, str, str, bool]:
        """Inspects ZIP contents to identify Office formats (DOCX/DOCM) vs generic archive."""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                namelist = zf.namelist()
                has_vba = any("vbaProject.bin" in name for name in namelist)
                has_word = any(name.startswith("word/") for name in namelist)
                has_excel = any(name.startswith("xl/") for name in namelist)
                has_ppt = any(name.startswith("ppt/") for name in namelist)

                if has_word:
                    if has_vba or client_ext == ".docm":
                        return "docm", ".docm", "application/vnd.ms-word.document.macroEnabled.12", False
                    return "docx", ".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", False
                elif has_excel:
                    if has_vba or client_ext == ".xlsm":
                        return "xlsm", ".xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", False
                    return "xlsx", ".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", False
                elif has_ppt:
                    if has_vba or client_ext == ".pptm":
                        return "pptm", ".pptm", "application/vnd.ms-powerpoint.presentation.macroEnabled.12", False
                    return "pptx", ".pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", False

                return "zip", ".zip", "application/zip", False
        except Exception:
            # Corrupted ZIP or encrypted ZIP
            return "zip", ".zip", "application/zip", False

    @classmethod
    def _looks_like_eml(cls, header: bytes) -> bool:
        """Heuristic check for RFC 822 email headers."""
        try:
            sample = header.decode("utf-8", errors="ignore").lower()
            eml_markers = ["from:", "to:", "subject:", "date:", "received:", "mime-version:", "message-id:", "content-type:"]
            matched = sum(1 for m in eml_markers if m in sample)
            return matched >= 2
        except Exception:
            return False

    @classmethod
    def _looks_like_text(cls, sample: bytes) -> bool:
        """Determines if sample bytes represent printable text."""
        if not sample:
            return False
        # Reject if byte 0 (null byte) is present (indicative of binary)
        if b"\x00" in sample:
            return False
        try:
            sample.decode("utf-8")
            return True
        except UnicodeDecodeError:
            try:
                sample.decode("latin-1")
                # Ensure high proportion of printable characters
                printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
                return (printable / len(sample)) > 0.85
            except Exception:
                return False
