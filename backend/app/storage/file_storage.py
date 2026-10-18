import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from pydantic import BaseModel

from app.core.config import settings


class StoredFileMetadata(BaseModel):
    storage_key: str
    file_path: str
    file_size_bytes: int
    sha256_hash: str
    mime_type: str
    created_at: str


class LocalFileStorage:
    """Isolated local filesystem storage for uploaded suspicious files.
    - Path-traversal immune
    - Server-generated UUID nonce filenames (never user-controlled names)
    - Stored outside web server root
    - Non-executable file permissions
    """

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir:
            self.base_path = Path(base_dir).resolve()
        else:
            self.base_path = Path(settings.FILE_STORAGE_DIR).resolve()
        self.base_path.mkdir(parents=True, exist_ok=True)

    def _resolve_safe_path(self, storage_key: str) -> Path:
        clean_key = os.path.basename(storage_key)
        target_path = (self.base_path / clean_key).resolve()
        try:
            target_path.relative_to(self.base_path)
        except ValueError:
            raise ValueError(f"Security error: path traversal detected for key '{storage_key}'.")
        return target_path

    async def save(
        self,
        file_bytes: bytes,
        extension: str,
        mime_type: str,
        sha256_hash: str,
    ) -> StoredFileMetadata:
        clean_ext = extension.lower() if extension.startswith(".") else f".{extension.lower()}"
        nonce = uuid.uuid4().hex
        storage_key = f"{nonce}{clean_ext}"
        target_path = self._resolve_safe_path(storage_key)

        with open(target_path, "wb") as f:
            f.write(file_bytes)

        # Remove execute permissions on Unix systems where applicable
        try:
            os.chmod(target_path, 0o600)
        except Exception:
            pass

        return StoredFileMetadata(
            storage_key=storage_key,
            file_path=str(target_path),
            file_size_bytes=len(file_bytes),
            sha256_hash=sha256_hash,
            mime_type=mime_type,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    async def get(self, storage_key: str) -> Optional[bytes]:
        target_path = self._resolve_safe_path(storage_key)
        if not target_path.is_file():
            return None
        with open(target_path, "rb") as f:
            return f.read()

    async def delete(self, storage_key: str) -> bool:
        target_path = self._resolve_safe_path(storage_key)
        if target_path.is_file():
            target_path.unlink()
            return True
        return False
