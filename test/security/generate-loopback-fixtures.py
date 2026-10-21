#!/usr/bin/env python3
"""Generate short-lived loopback certificates without changing fixed test keys.

Only Python's standard library and an installed OpenSSL CLI are required. These
fixtures are private test credentials, never system trust-store changes.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def find_openssl():
    """Find a runnable OpenSSL, including common Windows CI installations."""
    candidates = [os.environ.get("OPENSSL_EXECUTABLE"), shutil.which("openssl")]
    roots = [Path(os.environ[key]) for key in ("VCPKG_ROOT", "VCPKG_INSTALLATION_ROOT")
             if os.environ.get(key)]
    roots.extend([Path("C:/vcpkg"), Path("C:/vcpkg/installed")])
    for root in roots:
        for installed in (root, root / "installed"):
            candidates.extend(installed.glob("*/tools/openssl/openssl.exe"))
            candidates.extend(installed.glob("*/tools/openssl/bin/openssl.exe"))
    for env in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        if os.environ.get(env):
            root = Path(os.environ[env])
            candidates.extend([root / "Git/mingw64/bin/openssl.exe",
                               root / "Git/usr/bin/openssl.exe",
                               root / "Programs/Git/mingw64/bin/openssl.exe",
                               root / "OpenSSL-Win64/bin/openssl.exe"])
    for candidate in candidates:
        if not candidate:
            continue
        try:
            subprocess.run([str(candidate), "version"], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return str(candidate)
        except (OSError, subprocess.CalledProcessError):
            continue
    raise RuntimeError("OpenSSL CLI not found; set OPENSSL_EXECUTABLE to its executable")


def generate_fixtures(source, destination=None):
    """Return a fixture directory; caller removes it when destination is omitted.

    Fixed leaf keys preserve the SPKI values used by the denied-key test binary.
    The ephemeral CA private key is deleted before returning. Use a separate
    destination to leave the checked-in source fixtures unchanged.
    """
    source = Path(source).resolve()
    destination = (Path(destination).resolve() if destination is not None else
                   Path(tempfile.mkdtemp(prefix="mailspring-loopback-")))
    destination.mkdir(parents=True, exist_ok=True)
    openssl = find_openssl()

    def run(*args):
        result = subprocess.run([openssl, *map(str, args)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            raise RuntimeError("OpenSSL fixture generation failed: " +
                               result.stderr.decode(errors="replace"))

    # Work separately so failed generation never replaces existing fixtures and
    # no CA private key is left in the published fixture directory.
    with tempfile.TemporaryDirectory(prefix="mailspring-loopback-ca-") as work:
        work = Path(work)
        config = work / "certificates.cnf"
        config.write_text("""[req]
distinguished_name = dn
prompt = no
[dn]
CN = mail.example.test
[ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:mail.example.test,IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
""", encoding="ascii")
        run("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
            "-out", work / "ca-key.pem")
        run("req", "-new", "-x509", "-sha256", "-days", "398",
            "-key", work / "ca-key.pem", "-subj", "/CN=Mailspring ephemeral loopback CA",
            "-config", config, "-extensions", "ca", "-out", work / "curl-ca.pem")
        for serial, name in enumerate(("curl-server", "curl-redirect"), start=2):
            shutil.copyfile(source / (name + "-key.pem"), work / (name + "-key.pem"))
            run("req", "-new", "-sha256", "-key", work / (name + "-key.pem"),
                "-config", config, "-out", work / (name + ".csr"))
            run("x509", "-req", "-sha256", "-days", "397",
                "-in", work / (name + ".csr"), "-CA", work / "curl-ca.pem",
                "-CAkey", work / "ca-key.pem", "-set_serial", str(serial),
                "-extfile", config, "-extensions", "server", "-out", work / (name + ".pem"))
            run("verify", "-CAfile", work / "curl-ca.pem", "-purpose", "sslserver",
                "-verify_hostname", "mail.example.test", work / (name + ".pem"))
        for name in ("curl-ca.pem", "curl-server.pem", "curl-server-key.pem",
                     "curl-redirect.pem", "curl-redirect-key.pem"):
            shutil.copyfile(work / name, destination / name)
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Directory containing fixed test private keys")
    parser.add_argument("destination", type=Path, nargs="?")
    args = parser.parse_args()
    print(generate_fixtures(args.source, args.destination))
