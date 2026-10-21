#include "../../MailSync/MCPlatformTLSChain.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

static void require(bool value, const char *message)
{
    if (!value) throw std::runtime_error(message);
}

#if defined(__APPLE__) || defined(_WIN32)
static std::vector<unsigned char> readCertificate(const std::string &path)
{
    std::ifstream input(path.c_str(), std::ios::binary);
    require(static_cast<bool>(input), "Cannot read platform certificate fixture");
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(input),
                                     std::istreambuf_iterator<char>());
}
#endif

#if defined(__APPLE__)
static bool platformAccepts(const std::vector<unsigned char> &der)
{
    CFDataRef data = CFDataCreate(NULL, der.data(), static_cast<CFIndex>(der.size()));
    SecCertificateRef certificate = SecCertificateCreateWithData(NULL, data);
    CFRelease(data);
    require(certificate != NULL, "Apple could not parse certificate");
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    SecTrustRef trust = NULL;
    require(SecTrustCreateWithCertificates(certificate, policy, &trust) == errSecSuccess,
            "Cannot create Apple trust context");
    const void *value = certificate;
    CFArrayRef anchors = CFArrayCreate(NULL, &value, 1, &kCFTypeArrayCallBacks);
    require(SecTrustSetAnchorCertificates(trust, anchors) == errSecSuccess,
            "Cannot set test-only Apple trust anchor");
    require(SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
            "Cannot isolate test trust anchors");
    CFDateRef date = CFDateCreate(NULL, 1800000000.0 - 978307200.0);
    require(SecTrustSetVerifyDate(trust, date) == errSecSuccess, "Cannot set stable verification date");
    CFRelease(date);
    CFErrorRef error = NULL;
    require(SecTrustEvaluateWithError(trust, &error),
            "Fixture must be trusted before applying compromised-key policy");
    if (error) CFRelease(error);
    bool allowed = platformTrustCertificateKeysAllowed(trust);
    CFRelease(anchors);
    CFRelease(trust);
    CFRelease(policy);
    CFRelease(certificate);
    return allowed;
}
#elif defined(_WIN32)
static bool platformAccepts(const std::vector<unsigned char> &der)
{
    PCCERT_CONTEXT certificate = CertCreateCertificateContext(
        X509_ASN_ENCODING, der.data(), static_cast<DWORD>(der.size()));
    require(certificate != NULL, "Windows could not parse certificate");
    // Exercise the same traversal with a real Windows certificate context,
    // including a key present only at the trust-anchor position.
    CERT_CHAIN_ELEMENT element = {};
    element.cbSize = sizeof(element);
    element.pCertContext = certificate;
    PCERT_CHAIN_ELEMENT elements[] = { &element };
    CERT_SIMPLE_CHAIN simple = {};
    simple.cbSize = sizeof(simple);
    simple.cElement = 1;
    simple.rgpElement = elements;
    PCERT_SIMPLE_CHAIN chains[] = { &simple };
    CERT_CHAIN_CONTEXT context = {};
    context.cbSize = sizeof(context);
    context.cChain = 1;
    context.rgpChain = chains;
    bool allowed = platformCertificateChainKeysAllowed(&context);
    context.TrustStatus.dwErrorStatus = CERT_TRUST_IS_UNTRUSTED_ROOT;
    require(!platformCertificateChainKeysAllowed(&context), "Untrusted Windows chain accepted");
    CertFreeCertificateContext(certificate);
    return allowed;
}
#endif

int main(int argc, char **argv)
{
    try {
        require(argc == 2, "Expected fixture directory");
#if defined(__APPLE__) || defined(_WIN32)
        require(!checkPlatformTLSChain(NULL), "Missing TLS session accepted");
        curl_tlssessioninfo invalid = {};
        require(!checkPlatformTLSChain(&invalid), "Unknown TLS backend accepted");
#if defined(__APPLE__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        SSLContextRef session = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
        require(session != NULL, "Cannot create Apple TLS session");
        require(platformTLSIdentityIsStable(session), "Default Apple TLS identity policy is unsafe");
        require(SSLSetSessionOption(session, kSSLSessionOptionAllowServerIdentityChange, true) == noErr,
                "Cannot enable identity-change test policy");
        require(!platformTLSIdentityIsStable(session), "Certificate-changing renegotiation accepted");
        require(SSLSetSessionOption(session, kSSLSessionOptionAllowServerIdentityChange, false) == noErr,
                "Cannot restore stable identity test policy");
        require(platformTLSIdentityIsStable(session), "Stable Apple TLS identity policy rejected");
        CFRelease(session);
#pragma clang diagnostic pop
#endif
        const char *names[] = {
            "EM-DV-TLS-CA-G3B", "EM-DV-TLS-CA-G3C", "EM-EV-TLS-CA-G3B", "EM-EV-TLS-CA-G3C",
            "EM-OV-CS-CA-G3B", "EM-OV-CS-CA-G3C", "EM-OV-TLS-CA-G3B", "EM-OV-TLS-CA-G3C"
        };
        for (std::size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
            for (int cross = 0; cross != 2; ++cross) {
                require(!platformAccepts(readCertificate(std::string(argv[1]) + "/" + names[i] +
                        (cross ? "-AAA.der" : ".der"))), "Compromised platform chain accepted");
            }
        }
        require(platformAccepts(readCertificate(std::string(argv[1]) + "/unblocked.der")),
                "Healthy platform certificate rejected");
        std::cout << "Platform chains reject all sixteen compromised certificates and accept healthy key\n";
#else
        (void) argv;
        std::cout << "Platform-specific chain tests run on macOS and Windows\n";
#endif
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
