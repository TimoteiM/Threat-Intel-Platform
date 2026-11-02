"""
TLS Collector — retrieves and parses the certificate chain.

Captures: issuer, SANs, validity period, self-signed status,
wildcard status, chain depth, cert fingerprint.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from app.collectors.base import BaseCollector
from app.models.schemas import CollectorMeta, TLSEvidence

logger = logging.getLogger(__name__)


class TLSCollector(BaseCollector):
    name = "tls"
    supported_types = frozenset({"domain", "url"})

    def _collect(self) -> TLSEvidence:
        from urllib.parse import urlparse

        evidence = TLSEvidence()

        # For URL type extract the hostname; for domain use directly
        if self.observable_type == "url":
            parsed = urlparse(self.domain)
            tls_host = parsed.hostname or self.domain
        else:
            tls_host = self.domain

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection(
                (tls_host, 443), timeout=self.timeout
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=tls_host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)

        except ssl.SSLError as e:
            logger.debug(f"TLS SSL error for {self.domain}: {e}")
            evidence.present = False
            return evidence
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"TLS connection failed for {self.domain}: {e}")
            evidence.present = False
            return evidence

        if der_cert is None:
            evidence.present = False
            return evidence

        evidence.present = True
        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        # ── Basic fields ──
        evidence.issuer = cert.issuer.rfc4514_string()
        evidence.subject = cert.subject.rfc4514_string()
        evidence.serial_number = str(cert.serial_number)
        evidence.signature_algorithm = cert.signature_algorithm_oid._name
        evidence.cert_sha256 = hashlib.sha256(der_cert).hexdigest()

        # ── Validity ──
        evidence.valid_from = cert.not_valid_before_utc
        evidence.valid_to = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        if evidence.valid_to:
            evidence.valid_days_remaining = (evidence.valid_to - now).days

        # ── Issuer organization ──
        for attr in cert.issuer:
            if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                evidence.issuer_org = attr.value
                break

        # ── Subject Alternative Names ──
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            evidence.sans = san_ext.value.get_values_for_type(x509.DNSName)
            evidence.is_wildcard = any(s.startswith("*.") for s in evidence.sans)
        except x509.ExtensionNotFound:
            evidence.sans = []

        # ── Self-signed check ──
        evidence.is_self_signed = (cert.issuer == cert.subject)

        # ── Chain info (from the single leaf cert we have) ──
        # Full chain inspection would require connecting with verify_mode=CERT_NONE
        # and walking the chain — out of scope for v1.
        evidence.chain_length = 1

        # ── Store raw artifact ──
        self._store_artifact("cert_der", der_cert)

        return evidence

    def _empty_evidence(self, meta: CollectorMeta) -> TLSEvidence:
        return TLSEvidence(meta=meta)
