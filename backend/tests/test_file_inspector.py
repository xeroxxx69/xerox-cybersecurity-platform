import io
import zipfile
from app.analyzers.file.validator import FileValidator
from app.analyzers.file.inspector import FileInspector


def test_pdf_javascript_and_launch_detection():
    content = (
        b"%PDF-1.4\n"
        b"1 0 obj << /JavaScript (app.alert('pwned')) >> endobj\n"
        b"2 0 obj << /Launch << /F (cmd.exe) >> >> endobj\n"
        b"3 0 obj << /URI (https://evil-phish-portal.live/login) >> endobj\n"
        b"trailer << /Root 1 0 R >> %%EOF\n"
    )
    val = FileValidator.validate(content, client_filename="invoice_urgent.pdf")
    res = FileInspector.inspect(val)

    indicator_types = [f.indicator_type for f in res.findings]
    assert "PDF_EMBEDDED_JAVASCRIPT" in indicator_types
    assert "PDF_LAUNCH_ACTION" in indicator_types
    assert "https://evil-phish-portal.live/login" in res.extracted_urls


def test_office_vba_macro_and_auto_exec_detection():
    # Build a simulated docm in memory
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", "<w:document></w:document>")
        zf.writestr("word/vbaProject.bin", b"sub AutoOpen()\n Shell('cmd.exe /c powershell -enc ...')\n End Sub")
    data = buf.getvalue()

    val = FileValidator.validate(data, client_filename="malicious_macro.docm")
    res = FileInspector.inspect(val)

    indicator_types = [f.indicator_type for f in res.findings]
    assert "OFFICE_VBA_MACRO_PRESENT" in indicator_types
    assert "OFFICE_VBA_AUTO_EXEC" in indicator_types
    assert "OFFICE_VBA_DANGEROUS_CALL" in indicator_types


def test_eml_reply_to_mismatch_and_attachment():
    content = (
        b"From: Security Team <security@trusted-bank.com>\n"
        b"Reply-To: phisher@scam-server.xyz\n"
        b"Subject: Action Required: Account Compromise Alert\n"
        b"Date: Mon, 14 Sep 2026 12:00:00 +0000\n"
        b"Content-Type: multipart/mixed; boundary=\"frontier\"\n\n"
        b"--frontier\n"
        b"Content-Type: text/plain\n\n"
        b"Please open the attached security update: https://phishing-lure.xyz\n"
        b"--frontier\n"
        b"Content-Type: application/octet-stream\n"
        b"Content-Disposition: attachment; filename=\"SecurityPatch.scr\"\n\n"
        b"fake payload bytes\n"
        b"--frontier--\n"
    )
    val = FileValidator.validate(content, client_filename="urgent.eml")
    res = FileInspector.inspect(val)

    indicator_types = [f.indicator_type for f in res.findings]
    assert "EMAIL_REPLY_TO_MISMATCH" in indicator_types
    assert "EMAIL_DANGEROUS_ATTACHMENT" in indicator_types
    assert "https://phishing-lure.xyz" in res.extracted_urls


def test_zip_path_traversal_detection():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../Windows/System32/evil.dll", b"binary")
        zf.writestr("payload.exe", b"binary")
    data = buf.getvalue()

    val = FileValidator.validate(data, client_filename="slip.zip")
    res = FileInspector.inspect(val)

    indicator_types = [f.indicator_type for f in res.findings]
    assert "ZIP_SLIP_PATH_TRAVERSAL" in indicator_types
    assert "ZIP_NESTED_EXECUTABLE" in indicator_types


def test_executable_truthful_unsupported_handling():
    content = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 100
    val = FileValidator.validate(content, client_filename="sample.exe")
    res = FileInspector.inspect(val)

    assert res.is_executable is True
    assert res.metadata["execution_status"] == "UNSUPPORTED_SAFE_BY_DESIGN"
    assert "defensive containment" in res.metadata["disclaimer"].lower()
    indicator_types = [f.indicator_type for f in res.findings]
    assert "EXECUTABLE_BINARY_DETECTED" in indicator_types
