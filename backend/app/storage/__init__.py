"""
Storage factory — returns the right backend based on config.
"""

from app.config import get_settings
from app.storage.base import BaseStorage
from app.storage.local import LocalStorage


def get_storage() -> BaseStorage:
    """Return configured storage backend."""
    settings = get_settings()

    if settings.artifact_storage == "s3":
        from app.storage.s3 import S3Storage
        return S3Storage(
            bucket=settings.s3_bucket,
            endpoint_url=settings.s3_endpoint_url or None,
        )
    else:
        return LocalStorage(base_path=settings.artifact_local_path)
