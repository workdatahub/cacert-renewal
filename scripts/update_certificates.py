#!/usr/bin/env python3
"""Fetch TLS CA chains and update docs/cert/ + docs/info/ when certificate fingerprints change."""

from __future__ import annotations

import re
import ssl
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

ROOT = Path(__file__).resolve().parents[1]
DOMAINS_FILE = ROOT / "domains.list"
CERT_DIR = ROOT / "docs" / "cert"
INFO_DIR = ROOT / "docs" / "info"
OPENSSL_TIMEOUT = 30


def split_pem_chain(data: bytes) -> list[bytes]:
    blocks = re.findall(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        data,
        flags=re.DOTALL,
    )
    return [b + b"\n" for b in blocks]


def cert_from_pem(pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem)


def fingerprint_sha256(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex().upper()


def is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def verify_child_with_parent(child: x509.Certificate, parent_pem: bytes) -> bool:
    with tempfile.TemporaryDirectory() as td:
        child_path = Path(td) / "child.pem"
        parent_path = Path(td) / "parent.pem"
        child_path.write_bytes(child.public_bytes(Encoding.PEM))
        parent_path.write_bytes(parent_pem)
        p = subprocess.run(
            ["openssl", "verify", "-CAfile", str(parent_path), str(child_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=OPENSSL_TIMEOUT,
        )
        return p.returncode == 0


def load_system_roots() -> list[bytes]:
    paths = ssl.get_default_verify_paths()
    candidates: list[Path] = []
    if paths.cafile:
        candidates.append(Path(paths.cafile))
    if paths.capath:
        capath = Path(paths.capath)
        if capath.is_dir():
            candidates.extend(p for p in capath.iterdir() if p.is_file())

    roots: list[bytes] = []
    seen: set[bytes] = set()

    for path in candidates:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for pem in split_pem_chain(data):
            if pem in seen:
                continue
            try:
                cert = cert_from_pem(pem)
            except ValueError:
                continue
            if is_ca(cert):
                seen.add(pem)
                roots.append(pem)

    return roots


def fetch_server_chain(domain: str) -> list[bytes]:
    p = subprocess.run(
        [
            "openssl", "s_client",
            "-connect", f"{domain}:443",
            "-servername", domain,
            "-showcerts",
            "-verify_return_error",
        ],
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=OPENSSL_TIMEOUT,
    )

    blocks = split_pem_chain(p.stdout)
    if p.returncode != 0 and not blocks:
        raise RuntimeError(
            f"TLS connection failed for {domain}:\n"
            + p.stdout.decode("utf-8", errors="replace")[-4000:]
        )
    if not blocks:
        raise RuntimeError(f"No certificates received from {domain}")
    return blocks


def build_chain(server_pems: list[bytes], roots: list[bytes]) -> list[bytes]:
    """Return [leaf, intermediate..., root] for the server's verified chain."""
    server = [(cert_from_pem(p), p) for p in server_pems]
    server_by_subject: dict[str, list[bytes]] = {}
    for cert, pem in server:
        if is_ca(cert):
            server_by_subject.setdefault(cert.subject.rfc4514_string(), []).append(pem)

    root_by_subject: dict[str, list[bytes]] = {}
    for pem in roots:
        cert = cert_from_pem(pem)
        root_by_subject.setdefault(cert.subject.rfc4514_string(), []).append(pem)

    leaf = server[0][0]
    chain = [server[0][1]]
    current = leaf
    visited = {current.fingerprint(hashes.SHA256())}

    for _ in range(10):
        issuer = current.issuer.rfc4514_string()
        candidates = server_by_subject.get(issuer, []) + root_by_subject.get(issuer, [])
        found = None

        for pem in candidates:
            parent = cert_from_pem(pem)
            fp = parent.fingerprint(hashes.SHA256())
            if fp in visited:
                continue
            if verify_child_with_parent(current, pem):
                found = pem
                break

        if found is None:
            raise RuntimeError(
                "Could not build a trusted certificate chain: "
                f"{current.subject.rfc4514_string()} -> {issuer}"
            )

        parent = cert_from_pem(found)
        chain.append(found)
        visited.add(parent.fingerprint(hashes.SHA256()))

        if parent.subject == parent.issuer:
            return chain

        current = parent

    raise RuntimeError("Certificate chain is longer than the supported limit")


def write_if_changed(path: Path, data: bytes) -> bool:
    if path.exists() and path.read_bytes() == data:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return True


def update_domain(domain: str, roots: list[bytes]) -> bool:
    server_pems = fetch_server_chain(domain)
    chain = build_chain(server_pems, roots)

    # chain = leaf, intermediate0, intermediate1, ..., root
    # Publish only CA certificates; the server/leaf certificate is not needed.
    ca_pems = chain[1:]
    if not ca_pems:
        raise RuntimeError(f"{domain}: no CA certificates found")

    changed = False
    safe_domain = domain.replace("/", "_")

    for index, pem in enumerate(ca_pems[:-1]):
        cert = cert_from_pem(pem)
        if not is_ca(cert):
            raise RuntimeError(f"{domain}: non-CA certificate in intermediate position")
        changed |= write_if_changed(
            CERT_DIR / f"{safe_domain}.intermediate{index}.pem",
            cert.public_bytes(Encoding.PEM),
        )
        changed |= write_if_changed(
            INFO_DIR / f"{safe_domain}.intermediate{index}.info",
            (fingerprint_sha256(cert) + "\n").encode("ascii"),
        )

    root_cert = cert_from_pem(ca_pems[-1])
    if not is_ca(root_cert) or root_cert.subject != root_cert.issuer:
        raise RuntimeError(f"{domain}: final certificate is not a self-signed CA root")

    changed |= write_if_changed(
        CERT_DIR / f"{safe_domain}.root.pem",
        root_cert.public_bytes(Encoding.PEM),
    )
    changed |= write_if_changed(
        INFO_DIR / f"{safe_domain}.root.info",
        (fingerprint_sha256(root_cert) + "\n").encode("ascii"),
    )

    existing = sorted(CERT_DIR.glob(f"{safe_domain}.intermediate*.pem"))
    expected = {
        CERT_DIR / f"{safe_domain}.intermediate{i}.pem"
        for i in range(max(0, len(ca_pems) - 1))
    }
    for path in existing:
        if path not in expected:
            path.unlink()
            changed = True
            info = INFO_DIR / (path.stem + ".info")
            if info.exists():
                info.unlink()

    existing_info = sorted(INFO_DIR.glob(f"{safe_domain}.intermediate*.info"))
    expected_info = {
        INFO_DIR / f"{safe_domain}.intermediate{i}.info"
        for i in range(max(0, len(ca_pems) - 1))
    }
    for path in existing_info:
        if path not in expected_info:
            path.unlink()
            changed = True

    return changed


def main() -> None:
    domains = [
        line.strip()
        for line in DOMAINS_FILE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not domains:
        raise SystemExit("domains.list is empty")

    roots = load_system_roots()
    if not roots:
        raise SystemExit("No system CA roots found")

    any_changed = False
    for domain in domains:
        print(f"Checking {domain} ...")
        changed = update_domain(domain, roots)
        print("  changed" if changed else "  unchanged")
        any_changed |= changed

    print("CERTIFICATES_CHANGED=" + ("true" if any_changed else "false"))


if __name__ == "__main__":
    main()
