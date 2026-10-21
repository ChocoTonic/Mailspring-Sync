#ifndef MAILCORE_OPENSSL_PEER_IDENTITY_H
#define MAILCORE_OPENSSL_PEER_IDENTITY_H

#include <openssl/err.h>
#include <openssl/x509v3.h>

namespace mailcore { namespace security {

// Bind chain validation to the requested DNS name or IP address. SNI alone
// selects the server's certificate; it does not verify the server's identity.
static inline bool setCertificatePeerIdentity(X509_STORE_CTX *context, const char *hostname)
{
    if (context == NULL || hostname == NULL || hostname[0] == '\0') return false;
    if (X509_STORE_CTX_set_purpose(context, X509_PURPOSE_SSL_SERVER) != 1) return false;
    X509_VERIFY_PARAM *parameters = X509_STORE_CTX_get0_param(context);
    if (parameters == NULL) return false;
    if (X509_VERIFY_PARAM_set1_ip_asc(parameters, hostname) == 1) return true;
    // A DNS name is not an IP literal. Discard only this expected parse failure
    // before starting the actual certificate verification.
    ERR_clear_error();
    X509_VERIFY_PARAM_set_hostflags(parameters, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    return X509_VERIFY_PARAM_set1_host(parameters, hostname, 0) == 1;
}

} }
#endif
