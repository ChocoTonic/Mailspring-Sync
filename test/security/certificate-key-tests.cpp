#include "../../Vendor/mailcore2/src/core/security/MCBlockedPublicKeys.h"
#include "../../Vendor/mailcore2/src/core/security/MCOpenSSLPeerIdentity.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

using mailcore::security::checkCertificatePublicKey;
using mailcore::security::KeyAllowed;
using mailcore::security::KeyBlocked;
using mailcore::security::KeyInvalid;

static std::vector<unsigned char> read(const std::string &path)
{
    std::ifstream input(path.c_str(), std::ios::binary);
    if (!input) throw std::runtime_error("Cannot read fixture: " + path);
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(input),
                                     std::istreambuf_iterator<char>());
}

static void require(bool condition, const char *message)
{
    if (!condition) throw std::runtime_error(message);
}

static bool verifiesForName(const std::vector<unsigned char> &der, const char *hostname)
{
    const unsigned char *data = der.data();
    X509 *certificate = d2i_X509(NULL, &data, static_cast<long>(der.size()));
    require(certificate != NULL, "Cannot parse healthy identity fixture");
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *context = X509_STORE_CTX_new();
    require(store != NULL && context != NULL, "Cannot allocate verification context");
    require(X509_STORE_add_cert(store, certificate) == 1, "Cannot trust test certificate");
    require(X509_STORE_CTX_init(context, store, certificate, NULL) == 1,
            "Cannot initialize verification context");
    // A stable point inside both healthy fixtures' validity windows keeps the
    // identity regression independent of wall-clock expiration.
    X509_STORE_CTX_set_time(context, 0, 1800000000);
    bool result = mailcore::security::setCertificatePeerIdentity(context, hostname) &&
                  X509_verify_cert(context) == 1;
    X509_STORE_CTX_free(context);
    X509_STORE_free(store);
    X509_free(certificate);
    return result;
}

int main(int argc, char **argv)
{
    try {
        require(argc == 2, "Expected fixture directory");
        const char *names[] = {
            "EM-DV-TLS-CA-G3B", "EM-DV-TLS-CA-G3C",
            "EM-EV-TLS-CA-G3B", "EM-EV-TLS-CA-G3C",
            "EM-OV-CS-CA-G3B", "EM-OV-CS-CA-G3C",
            "EM-OV-TLS-CA-G3B", "EM-OV-TLS-CA-G3C"
        };
        for (std::size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
            for (int crossSigned = 0; crossSigned != 2; ++crossSigned) {
                std::string path = std::string(argv[1]) + "/" + names[i] +
                    (crossSigned ? "-AAA.der" : ".der");
                std::vector<unsigned char> cert = read(path);
                require(checkCertificatePublicKey(cert.data(), cert.size()) == KeyBlocked,
                        "A compromised original or cross-signed key was accepted");
                std::vector<unsigned char> nonminimal = cert;
                nonminimal.insert(nonminimal.begin() + 2, 0);
                nonminimal[1] += 1;
                require(checkCertificatePublicKey(nonminimal.data(), nonminimal.size()) == KeyInvalid,
                        "A nonminimal DER length was accepted");
                for (std::size_t length = 0; length < cert.size(); ++length) {
                    require(checkCertificatePublicKey(cert.data(), length) == KeyInvalid,
                            "A truncated certificate bypassed the key check");
                }
                cert[0] = 0x31;
                require(checkCertificatePublicKey(cert.data(), cert.size()) == KeyInvalid,
                        "An invalid outer certificate tag was accepted");
                cert[0] = 0x30;
                cert[1] = 0x80;
                require(checkCertificatePublicKey(cert.data(), cert.size()) == KeyInvalid,
                        "An indefinite DER length was accepted");
                cert[1] = 0xff;
                require(checkCertificatePublicKey(cert.data(), cert.size()) == KeyInvalid,
                        "An overflowing DER length was accepted");
            }
        }
        std::vector<unsigned char> healthy = read(std::string(argv[1]) + "/unblocked.der");
        require(checkCertificatePublicKey(healthy.data(), healthy.size()) == KeyAllowed,
                "An unrelated healthy certificate was blocked");
        std::vector<unsigned char> v1 = read(std::string(argv[1]) + "/unblocked-v1.der");
        require(checkCertificatePublicKey(v1.data(), v1.size()) == KeyAllowed,
                "A healthy v1 certificate without an explicit version was blocked");
        require(verifiesForName(healthy, "mail.example.test"), "Matching DNS SAN rejected");
        require(!verifiesForName(healthy, "attacker.example.test"), "Wrong DNS name accepted");
        require(verifiesForName(healthy, "127.0.0.1"), "Matching IPv4 SAN rejected");
        require(!verifiesForName(healthy, "127.0.0.2"), "Wrong IPv4 address accepted");
        require(verifiesForName(healthy, "::1"), "Matching IPv6 SAN rejected");
        require(!verifiesForName(healthy, "::2"), "Wrong IPv6 address accepted");
        require(!verifiesForName(healthy, ""), "Empty hostname accepted");
        require(!verifiesForName(healthy, NULL), "Null hostname accepted");
        require(verifiesForName(v1, "mail.example.test"), "Matching legacy CN rejected");
        require(!verifiesForName(v1, "attacker.example.test"), "Wrong legacy CN accepted");
        std::vector<unsigned char> client = read(std::string(argv[1]) + "/client-auth-only.der");
        require(!verifiesForName(client, "mail.example.test"),
                "A client-auth-only certificate was accepted as a TLS server");
        require(checkCertificatePublicKey(NULL, 1) == KeyInvalid, "Null input was accepted");
        unsigned char empty[] = {0x30, 0};
        require(checkCertificatePublicKey(empty, sizeof(empty)) == KeyInvalid,
                "An empty certificate was accepted");
        std::cout << "16 compromised certificates (eight keys, two issuers) blocked; "
                     "healthy, malformed input, DNS and IP identity regressions passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
