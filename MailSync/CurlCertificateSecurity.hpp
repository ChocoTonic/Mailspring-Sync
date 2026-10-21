#ifndef MAILSYNC_CURL_CERTIFICATE_SECURITY_HPP
#define MAILSYNC_CURL_CERTIFICATE_SECURITY_HPP

#include <curl/curl.h>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include "../Vendor/mailcore2/src/core/security/MCBlockedPublicKeys.h"
#if defined(__APPLE__) || defined(_WIN32)
#include "MCPlatformTLSChain.h"
#endif
#if !defined(__APPLE__)
#include <openssl/ssl.h>
#endif

#if !defined(__APPLE__)
static inline bool CurlUsesCompatibleOpenSSL()
{
    const curl_version_info_data *version = curl_version_info(CURLVERSION_NOW);
    if (version == NULL || version->ssl_version == NULL ||
        std::strncmp(version->ssl_version, "OpenSSL/", 8) != 0) return false;
    char *end = NULL;
    unsigned long major = std::strtoul(version->ssl_version + 8, &end, 10);
    unsigned long linked = OpenSSL_version_num();
    if (end == NULL || *end != '.' || major != (linked >> 28)) return false;
    // OpenSSL 1.0 and 1.1 are not ABI compatible despite sharing the major.
    return major != 1 || std::strtoul(end + 1, NULL, 10) == ((linked >> 20) & 0xff);
}

static inline bool CheckCurlOpenSSLChain(STACK_OF(X509) *chain)
{
    if (chain == NULL || sk_X509_num(chain) == 0) return false;
    for (int i = 0; i < sk_X509_num(chain); ++i) {
        unsigned char *der = NULL;
        int length = i2d_X509(sk_X509_value(chain, i), &der);
        mailcore::security::CertificateKeyStatus status = length <= 0 ?
            mailcore::security::KeyInvalid : mailcore::security::checkCertificatePublicKey(
                der, static_cast<std::size_t>(length));
        OPENSSL_free(der);
        if (status != mailcore::security::KeyAllowed) return false;
    }
    return true;
}

static inline int VerifyCurlOpenSSLChain(X509_STORE_CTX *context, void *)
{
    if (X509_verify_cert(context) != 1) return 0;
    if (CheckCurlOpenSSLChain(X509_STORE_CTX_get0_chain(context))) return 1;
    X509_STORE_CTX_set_error(context, X509_V_ERR_CERT_REVOKED);
    return 0;
}

static inline CURLcode ConfigureCurlOpenSSLContext(CURL *, void *context, void *)
{
    if (context == NULL || !CurlUsesCompatibleOpenSSL()) return CURLE_SSL_CERTPROBLEM;
    SSL_CTX *sslContext = static_cast<SSL_CTX *>(context);
    SSL_CTX_set_options(sslContext, SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_cert_verify_callback(sslContext, VerifyCurlOpenSSLChain, NULL);
    return CURLE_OK;
}
#endif

static inline bool InitializeCurlCertificateSecurity()
{
#if defined(__APPLE__)
    // Apple ships a MultiSSL libcurl whose default can be LibreSSL. Select the
    // backend whose verified SecTrust chain we inspect before any curl init.
    if (curl_global_sslset(CURLSSLBACKEND_SECURETRANSPORT, NULL, NULL) != CURLSSLSET_OK)
        return false;
#endif
    return curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK;
}

static inline bool CheckCurlTLSCertificateChain(const curl_tlssessioninfo *information)
{
    if (information == NULL || information->internals == NULL) return false;
#if defined(__APPLE__)
    if (information->backend == CURLSSLBACKEND_SECURETRANSPORT) {
        return checkPlatformTLSChain(information);
    }
#endif
#if !defined(__APPLE__)
    if (information->backend == CURLSSLBACKEND_OPENSSL) {
        // LibreSSL/BoringSSL also use this backend identifier. Their SSL
        // structures cannot safely be passed to our linked OpenSSL library.
        if (!CurlUsesCompatibleOpenSSL()) return false;
        SSL *connection = static_cast<SSL *>(information->internals);
        if (SSL_get_verify_result(connection) != X509_V_OK) return false;
        return CheckCurlOpenSSLChain(SSL_get0_verified_chain(connection));
    }
#endif
    return false;
}

#if LIBCURL_VERSION_NUM >= 0x075000
static inline int CheckCurlPeerBeforeRequest(void *userData, char *, char *, int, int)
{
    CURL *handle = static_cast<CURL *>(userData);
    if (handle == NULL) return CURL_PREREQFUNC_ABORT;
    char *scheme = NULL;
    if (curl_easy_getinfo(handle, CURLINFO_SCHEME, &scheme) != CURLE_OK || scheme == NULL)
        return CURL_PREREQFUNC_ABORT;
    // Preserve explicitly configured plaintext HTTP CalDAV accounts. HTTPS
    // must expose a verified chain before any request headers or body are sent.
    if (std::strcmp(scheme, "http") == 0) return CURL_PREREQFUNC_OK;
    if (std::strcmp(scheme, "https") != 0) return CURL_PREREQFUNC_ABORT;
    curl_tlssessioninfo *information = NULL;
    if (curl_easy_getinfo(handle, CURLINFO_TLS_SSL_PTR, &information) != CURLE_OK)
        return CURL_PREREQFUNC_ABORT;
    return CheckCurlTLSCertificateChain(information) ? CURL_PREREQFUNC_OK : CURL_PREREQFUNC_ABORT;
}
#endif

static inline bool ConfigureCurlCertificateSecurity(CURL *handle)
{
#if LIBCURL_VERSION_NUM >= 0x075000
    const curl_version_info_data *version = curl_version_info(CURLVERSION_NOW);
    if (handle == NULL || version == NULL || version->version_num < 0x075000) return false;
#if !defined(__APPLE__)
    // The distributed Windows build explicitly selects OpenSSL as well.
    if (!CurlUsesCompatibleOpenSSL() ||
        curl_easy_setopt(handle, CURLOPT_SSL_CTX_FUNCTION, ConfigureCurlOpenSSLContext) != CURLE_OK)
        return false;
#else
    // A TLS proxy can send CONNECT authentication before the origin pre-request
    // callback. SecureTransport exposes no pre-handshake verification hook, so
    // reject this unsupported configuration before any network operation.
    const char *proxyVariables[] = { "https_proxy", "HTTPS_PROXY", "http_proxy",
                                    "HTTP_PROXY", "all_proxy", "ALL_PROXY" };
    for (std::size_t i = 0; i < sizeof(proxyVariables) / sizeof(proxyVariables[0]); ++i) {
        const char *proxy = std::getenv(proxyVariables[i]);
        if (proxy == NULL) continue;
        while (*proxy && std::isspace(static_cast<unsigned char>(*proxy))) ++proxy;
        const char scheme[] = "https://";
        std::size_t j = 0;
        while (scheme[j] && proxy[j] &&
               std::tolower(static_cast<unsigned char>(proxy[j])) == scheme[j]) ++j;
        if (scheme[j] == '\0') return false;
    }
    if (version->ssl_version == NULL ||
        std::strncmp(version->ssl_version, "SecureTransport", 15) != 0) return false;
#endif
    return curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1L) == CURLE_OK &&
           curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 2L) == CURLE_OK &&
           // A resumed session may not expose the verified certificate chain.
           // Reusing an already verified connection remains supported.
           curl_easy_setopt(handle, CURLOPT_SSL_SESSIONID_CACHE, 0L) == CURLE_OK &&
           curl_easy_setopt(handle, CURLOPT_PREREQFUNCTION, CheckCurlPeerBeforeRequest) == CURLE_OK &&
           curl_easy_setopt(handle, CURLOPT_PREREQDATA, handle) == CURLE_OK;
#else
    (void)handle;
    return false;
#endif
}

#endif
