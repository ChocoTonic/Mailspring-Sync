#ifndef MAILSYNC_PLATFORM_TLS_CHAIN_H
#define MAILSYNC_PLATFORM_TLS_CHAIN_H

#include <curl/curl.h>
#include "../Vendor/mailcore2/src/core/security/MCBlockedPublicKeys.h"

#if defined(__APPLE__)
#include <Security/Security.h>
#include <Security/SecureTransport.h>

// This adds key blocking to libcurl's normal peer/hostname validation. It runs
// from the pre-request callback, before HTTP headers or credentials are sent.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static inline bool platformTLSIdentityIsStable(SSLContextRef context)
{
    if (!context) return false;
    // SecureTransport rejects any byte change to the complete peer certificate
    // chain on renegotiation when this option is false. Unlike setting session
    // options, reading this policy is valid after the initial handshake.
    // Apple coreTLS 0e31699, lib/sslCert.c: CertificateChainEqual and its caller.
    Boolean allowsChange = true;
    return SSLGetSessionOption(context, kSSLSessionOptionAllowServerIdentityChange,
                               &allowsChange) == noErr && !allowsChange;
}

static inline bool platformTrustCertificateKeysAllowed(SecTrustRef trust)
{
    if (!trust) return false;
    CFErrorRef error = NULL;
    bool allowed = SecTrustEvaluateWithError(trust, &error);
    if (error) CFRelease(error);
    CFIndex count = allowed ? SecTrustGetCertificateCount(trust) : 0;
    if (count <= 0) allowed = false;
    for (CFIndex i = 0; allowed && i < count; ++i) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(trust, i);
        CFDataRef der = certificate ? SecCertificateCopyData(certificate) : NULL;
        if (!der) {
            allowed = false;
            break;
        }
        CFIndex length = CFDataGetLength(der);
        allowed = length > 0 && mailcore::security::checkCertificatePublicKey(
            CFDataGetBytePtr(der), static_cast<std::size_t>(length)) == mailcore::security::KeyAllowed;
        CFRelease(der);
    }
    return allowed;
}

static inline bool checkPlatformTLSChain(const curl_tlssessioninfo *info)
{
    if (!info || info->backend != CURLSSLBACKEND_SECURETRANSPORT || !info->internals)
        return false;
    SSLContextRef context = static_cast<SSLContextRef>(info->internals);
    if (!platformTLSIdentityIsStable(context)) return false;
    SecTrustRef trust = NULL;
    if (SSLCopyPeerTrust(context, &trust) != noErr || !trust) {
        if (trust) CFRelease(trust);
        return false;
    }
    bool allowed = platformTrustCertificateKeysAllowed(trust);
    CFRelease(trust);
    return allowed;
}
#pragma clang diagnostic pop

#elif defined(_WIN32)
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib")

static inline bool platformCertificateKeyAllowed(PCCERT_CONTEXT certificate)
{
    return certificate && mailcore::security::checkCertificatePublicKey(
        certificate->pbCertEncoded, certificate->cbCertEncoded) == mailcore::security::KeyAllowed;
}

static inline bool platformCertificateChainKeysAllowed(PCCERT_CHAIN_CONTEXT chain)
{
    if (!chain || !chain->cChain || chain->TrustStatus.dwErrorStatus != CERT_TRUST_NO_ERROR)
        return false;
    for (DWORD i = 0; i < chain->cChain; ++i) {
        PCERT_SIMPLE_CHAIN simple = chain->rgpChain[i];
        if (!simple || !simple->cElement) return false;
        for (DWORD j = 0; j < simple->cElement; ++j) {
            if (!simple->rgpElement[j] ||
                !platformCertificateKeyAllowed(simple->rgpElement[j]->pCertContext)) return false;
        }
    }
    return true;
}

static inline bool checkPlatformTLSChain(const curl_tlssessioninfo *info)
{
    if (!info || info->backend != CURLSSLBACKEND_SCHANNEL || !info->internals)
        return false;
    PCCERT_CONTEXT peer = NULL;
    if (QueryContextAttributesA(static_cast<CtxtHandle *>(info->internals),
                               SECPKG_ATTR_REMOTE_CERT_CONTEXT, &peer) != SEC_E_OK || !peer) {
        if (peer) CertFreeCertificateContext(peer);
        return false;
    }

    bool allowed = platformCertificateKeyAllowed(peer);
    // Schannel's remote certificate store contains the certificates received
    // from the peer. Inspect it as well as the built chain, so an alternate
    // trust path cannot hide a compromised cross-signed certificate.
    if (allowed && peer->hCertStore) {
        PCCERT_CONTEXT certificate = NULL;
        while ((certificate = CertEnumCertificatesInStore(peer->hCertStore, certificate)) != NULL) {
            if (!platformCertificateKeyAllowed(certificate)) {
                allowed = false;
                CertFreeCertificateContext(certificate);
                break;
            }
        }
        if (allowed && GetLastError() != static_cast<DWORD>(CRYPT_E_NOT_FOUND)) allowed = false;
    }

    CERT_CHAIN_PARA parameters = {};
    parameters.cbSize = sizeof(parameters);
    PCCERT_CHAIN_CONTEXT chain = NULL;
    if (allowed) {
        allowed = CertGetCertificateChain(NULL, peer, NULL, peer->hCertStore,
                                         &parameters, 0, NULL, &chain) != FALSE;
        allowed = allowed && platformCertificateChainKeysAllowed(chain);
    }
    if (chain) CertFreeCertificateChain(chain);
    CertFreeCertificateContext(peer);
    return allowed;
}
#endif
#endif
