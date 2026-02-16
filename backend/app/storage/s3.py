"""
S3-compatible storage — for production (AWS S3 or MinIO).

Artifacts stored at: s3://{bucket}/{investigation_id}/{artifact_name}
"""

from __future__ import annotations

from typing import Optional

import boto3
from botocore.exceptions import ClientError

from app.storage.base import BaseStorage


class S3Storage(BaseStorage):

    def __init__(
        self,
        bucket: str,
        endpoint_url: Optional[str] = None,
        region_name: str = "us-east-1",
    ):
        self.bucket = bucket
        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            region_name=region_name,
        )
        # Ensure bucket exists
        try:
            self.client.head_bucket(Bucket=bucket)
        except ClientError:
            self.client.create_bucket(Bucket=bucket)

    def _get_key(self, investigation_id: str, artifact_name: str) -> str:
        safe_name = artifact_name.replace("..", "_")
        return f"{investigation_id}/{safe_name}"

    async def save(
        self,
        investigation_id: str,
        artifact_name: str,
        data: bytes,
        content_type: Optional[str] = None,
    ) -> str:
        key = self._get_key(investigation_id, artifact_name)
        extra_args = {}
        if content_type:
            extra_args["ContentType"] = content_type

        self.client.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=data,
            **extra_args,
        )
        return f"s3://{self.bucket}/{key}"

    async def load(self, storage_path: str) -> bytes:
        # Parse s3://bucket/key
        path = storage_path.replace("s3://", "")
        bucket, key = path.split("/", 1)
        response = self.client.get_object(Bucket=bucket, Key=key)
        return response["Body"].read()

    async def exists(self, storage_path: str) -> bool:
        path = storage_path.replace("s3://", "")
        bucket, key = path.split("/", 1)
        try:
            self.client.head_object(Bucket=bucket, Key=key)
            return True
        except ClientError:
            return False

    async def delete(self, storage_path: str) -> None:
        path = storage_path.replace("s3://", "")
        bucket, key = path.split("/", 1)
        self.client.delete_object(Bucket=bucket, Key=key)
