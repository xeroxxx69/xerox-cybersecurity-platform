import pytest
from app.analyzers.file.validator import FileValidator, FileValidationError


def test_valid_pdf_validation():
    content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
    res = FileValidator.validate(content, client_filename="invoice.pdf")
    assert res.detected_format == "pdf"
    assert res.safe_extension == ".pdf"
    assert res.mime_type == "application/pdf"
    assert not res.is_executable
    assert len(res.sha256_hash) == 64
    assert res.client_filename == "invoice.pdf"


def test_valid_text_validation():
    content = b"Hello, this is a plain text security document."
    res = FileValidator.validate(content, client_filename="notes.txt")
    assert res.detected_format == "text"
    assert res.safe_extension == ".txt"
    assert not res.is_executable


def test_eml_validation():
    content = (
        b"From: sender@example.com\n"
        b"To: recipient@example.com\n"
        b"Subject: Test Subject\n"
        b"Date: Mon, 14 Sep 2026 10:00:00 +0000\n"
        b"Content-Type: text/plain\n\n"
        b"Body content here"
    )
    res = FileValidator.validate(content, client_filename="phish.eml")
    assert res.detected_format == "eml"
    assert res.safe_extension == ".eml"
    assert res.mime_type == "message/rfc822"
    assert not res.is_executable


def test_executable_pe_detection():
    content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 100
    res = FileValidator.validate(content, client_filename="payload.exe")
    assert res.is_executable is True
    assert res.detected_format == "executable"
    assert res.safe_extension == ".exe"


def test_executable_elf_detection():
    content = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100
    res = FileValidator.validate(content, client_filename="rootkit")
    assert res.is_executable is True
    assert res.detected_format == "executable"


def test_empty_file_rejected():
    with pytest.raises(FileValidationError, match="0 bytes"):
        FileValidator.validate(b"", client_filename="empty.txt")


def test_oversized_file_rejected():
    oversized = b"A" * (16 * 1024 * 1024)  # 16 MB > 15 MB limit
    with pytest.raises(FileValidationError, match="exceeds maximum allowed limit"):
        FileValidator.validate(oversized, client_filename="big.zip")


def test_filename_sanitization_and_traversal_guards():
    content = b"%PDF-1.4\nsome content"
    res = FileValidator.validate(content, client_filename="../../etc/passwd\x00.pdf")
    assert ".." not in res.client_filename
    assert "\x00" not in res.client_filename
    assert "/" not in res.client_filename
    assert "\\" not in res.client_filename
