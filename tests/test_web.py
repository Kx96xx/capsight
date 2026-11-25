"""Web demo logic, tested without importing gradio."""

import shutil

from conftest import needs_tshark

from capsight.web import diagnose


def test_no_file():
    assert diagnose(None) == "Upload a capture first."


def test_wrong_extension(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("hi")
    assert "Unsupported file type" in diagnose(str(f))


@needs_tshark
def test_upload_is_diagnosed_and_deleted(ula_user_unknown, tmp_path):
    upload = tmp_path / "customer.pcap"
    shutil.copyfile(ula_user_unknown, upload)
    out = diagnose(str(upload))
    assert "ULR rejected: DIAMETER_ERROR_USER_UNKNOWN." in out
    assert "capture   customer.pcap" in out
    assert not upload.exists()
