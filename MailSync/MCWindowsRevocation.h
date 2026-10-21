#ifndef MAILSYNC_WINDOWS_REVOCATION_H
#define MAILSYNC_WINDOWS_REVOCATION_H

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#pragma comment(lib, "Crypt32.lib")

struct NativeWindowsChainResources {
    HCERTSTORE certificates;
    HCERTSTORE anchors;
    PCCERT_CONTEXT peer;
    HCERTCHAINENGINE engine;
    PCCERT_CHAIN_CONTEXT chain;

    NativeWindowsChainResources()
        : certificates(NULL), anchors(NULL), peer(NULL), engine(NULL), chain(NULL) {}
    ~NativeWindowsChainResources()
    {
        if (chain) CertFreeCertificateChain(chain);
        if (engine) CertFreeCertificateChainEngine(engine);
        if (peer) CertFreeCertificateContext(peer);
        if (anchors) CertCloseStore(anchors, 0);
        if (certificates) CertCloseStore(certificates, 0);
    }
    NativeWindowsChainResources(const NativeWindowsChainResources &) = delete;
    NativeWindowsChainResources &operator=(const NativeWindowsChainResources &) = delete;
};

static inline bool NativeWindowsRevocationFailure(X509_STORE_CTX *context, DWORD errors)
{
    if (context) {
        int reason = X509_V_ERR_CERT_REJECTED;
        if (errors & CERT_TRUST_IS_REVOKED) reason = X509_V_ERR_CERT_REVOKED;
        else if (errors & (CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION))
            reason = X509_V_ERR_UNABLE_TO_GET_CRL;
        X509_STORE_CTX_set_error(context, reason);
    }
    return false;
}

// Call only after OpenSSL has verified the chain against its configured trust
// sources. Importing Windows roots into OpenSSL does not import Schannel's
// revocation policy, so retain that additional platform check explicitly.
// All stores/anchors below are private in-memory objects; the OS trust stores
// are never modified. The last already-verified OpenSSL certificate supplies
// the trust anchor, preserving explicit CAINFO configurations as well.
static inline bool NativeWindowsRevocationCheck(X509_STORE_CTX *context)
{
    if (!context) return false;
    STACK_OF(X509) *verified = X509_STORE_CTX_get0_chain(context);
    int count = verified ? sk_X509_num(verified) : 0;
    if (count <= 0) return NativeWindowsRevocationFailure(context, 0);

    NativeWindowsChainResources resources;
    resources.certificates = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
                                           CERT_STORE_CREATE_NEW_FLAG, NULL);
    resources.anchors = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
                                     CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!resources.certificates || !resources.anchors)
        return NativeWindowsRevocationFailure(context, 0);

    for (int i = 0; i < count; ++i) {
        unsigned char *der = NULL;
        int length = i2d_X509(sk_X509_value(verified, i), &der);
        PCCERT_CONTEXT certificate = length > 0 ? CertCreateCertificateContext(
            X509_ASN_ENCODING, der, static_cast<DWORD>(length)) : NULL;
        OPENSSL_free(der);
        if (!certificate) return NativeWindowsRevocationFailure(context, 0);

        bool added = CertAddCertificateContextToStore(resources.certificates, certificate,
                                                       CERT_STORE_ADD_ALWAYS, NULL) != FALSE;
        if (i == 0) {
            resources.peer = CertDuplicateCertificateContext(certificate);
            added = added && resources.peer != NULL;
        }
        if (i == count - 1) {
            added = added && CertAddCertificateContextToStore(resources.anchors, certificate,
                                                               CERT_STORE_ADD_ALWAYS, NULL) != FALSE;
        }
        CertFreeCertificateContext(certificate);
        if (!added) return NativeWindowsRevocationFailure(context, 0);
    }

    CERT_CHAIN_ENGINE_CONFIG configuration = {};
    configuration.cbSize = sizeof(configuration);
    configuration.hExclusiveRoot = resources.anchors;
#if defined(NTDDI_VERSION) && defined(NTDDI_WIN8) && NTDDI_VERSION >= NTDDI_WIN8
    configuration.dwExclusiveFlags = CERT_CHAIN_EXCLUSIVE_ENABLE_CA_FLAG;
#endif
    configuration.dwUrlRetrievalTimeout = 15000;
    if (!CertCreateCertificateChainEngine(&configuration, &resources.engine))
        return NativeWindowsRevocationFailure(context, 0);

    CERT_CHAIN_PARA parameters = {};
    parameters.cbSize = sizeof(parameters);
    LPSTR serverAuth = const_cast<char *>(szOID_PKIX_KP_SERVER_AUTH);
    parameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    parameters.RequestedUsage.Usage.cUsageIdentifier = 1;
    parameters.RequestedUsage.Usage.rgpszUsageIdentifier = &serverAuth;
    if (!CertGetCertificateChain(resources.engine, resources.peer, NULL, resources.certificates,
                                 &parameters, CERT_CHAIN_REVOCATION_CHECK_CHAIN |
                                 CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT,
                                 NULL, &resources.chain) || !resources.chain ||
        !resources.chain->cChain)
        return NativeWindowsRevocationFailure(context, 0);

    DWORD errors = resources.chain->TrustStatus.dwErrorStatus;
    if (errors != CERT_TRUST_NO_ERROR)
        return NativeWindowsRevocationFailure(context, errors);
    return true;
}
#endif
#endif
