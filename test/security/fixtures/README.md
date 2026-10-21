The 16 public eMudhra certificates are DER conversions of the original and
AAA-cross-signed certificates attached to Mozilla's incident report:

- https://bugzilla.mozilla.org/attachment.cgi?id=9664066
- https://bugzilla.mozilla.org/attachment.cgi?id=9664067

Their eight SubjectPublicKeyInfo SHA-256 hashes match Node.js PR 66871 and
Electron PR 55126. No private keys or attestation signatures are included.
`unblocked.der`, `unblocked-v1.der`, and `client-auth-only.der` are self-signed,
unrelated P-256 certificates created only for this regression test. Their
private key was discarded. They exercise a healthy DNS/IP server certificate,
a legacy v1 certificate without an explicit version field, and rejection of a
client-only extended key usage respectively.
