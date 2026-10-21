#include "../../MailSync/CurlCertificateSecurity.hpp"
#include <iostream>
#include <string>

static size_t discard(char *, size_t size, size_t count, void *) { return size * count; }

static int diagnosePeer(void *data, char *primary, char *local, int remotePort, int localPort)
{
    int result = CheckCurlPeerBeforeRequest(data, primary, local, remotePort, localPort);
    if (result != CURL_PREREQFUNC_OK) {
        CURL *handle = static_cast<CURL *>(data);
        char *scheme = NULL;
        curl_tlssessioninfo *tls = NULL;
        CURLcode schemeResult = curl_easy_getinfo(handle, CURLINFO_SCHEME, &scheme);
        CURLcode tlsResult = curl_easy_getinfo(handle, CURLINFO_TLS_SSL_PTR, &tls);
        std::cerr << "Rejected peer: schemeResult=" << schemeResult << " scheme="
                  << (scheme ? scheme : "null") << " tlsResult=" << tlsResult
                  << " backend=" << (tls ? static_cast<int>(tls->backend) : -1)
                  << " internals=" << (tls ? tls->internals : NULL) << '\n';
#if !defined(__APPLE__)
        if (tls && tls->internals && tls->backend == CURLSSLBACKEND_OPENSSL && CurlUsesCompatibleOpenSSL()) {
            SSL *ssl = static_cast<SSL *>(tls->internals);
            std::cerr << "OpenSSL verify=" << SSL_get_verify_result(ssl)
                      << " chain=" << SSL_get0_verified_chain(ssl) << '\n';
        }
#endif
    }
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 4 || !InitializeCurlCertificateSecurity()) return 2;
    CURL *handle = curl_easy_init();
    bool configured = ConfigureCurlCertificateSecurity(handle);
    std::string expected = argv[3];
    if (expected == "configure-denied") {
        curl_easy_cleanup(handle);
        curl_global_cleanup();
        return configured ? 3 : 0;
    }
    if (!configured) {
        std::cerr << "Unsupported TLS runtime: " << curl_version() << '\n';
        curl_easy_cleanup(handle);
        return 4;
    }
    curl_easy_setopt(handle, CURLOPT_PREREQFUNCTION, diagnosePeer);
    curl_easy_setopt(handle, CURLOPT_URL, argv[1]);
    curl_easy_setopt(handle, CURLOPT_PROXY, "");
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(handle, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, "credential=local-regression-only");
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, discard);
    if (std::string(argv[2]) != "-") curl_easy_setopt(handle, CURLOPT_CAINFO, argv[2]);
    curl_slist *headers = curl_slist_append(NULL, "Authorization: Bearer local-regression-only");
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
    int result = 0;
    for (int i = 0; i != 2; ++i) {
        CURLcode code = curl_easy_perform(handle);
        if (expected == "deny") {
            if (code == CURLE_OK) result = 5;
            break;
        }
        if (code != CURLE_OK) {
            std::cerr << "HTTPS request failed: " << curl_easy_strerror(code) << '\n';
            result = 6;
            break;
        }
        long connections = 0;
        curl_easy_getinfo(handle, CURLINFO_NUM_CONNECTS, &connections);
        if (i == 1 && connections != 0) {
            std::cerr << "The repeat request did not reuse its verified connection\n";
            result = 7;
        }
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(handle);
    curl_global_cleanup();
    return result;
}
