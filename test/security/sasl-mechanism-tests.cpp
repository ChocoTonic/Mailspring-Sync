#include "../../Vendor/libetpan/src/data-types/mailsasl_security.h"
#include <cstdlib>
#include <iostream>

int main() {
  const char *denied[] = {"DIGEST-MD5", "digest-md5", "DiGeSt-Md5", "PLAIN DIGEST-MD5", "\tDIGEST-MD5\r\nLOGIN", "SCRAM-SHA-256 digest-md5 XOAUTH2"};
  const char *allowed[] = {"PLAIN", "LOGIN", "CRAM-MD5", "SCRAM-SHA-256", "XOAUTH2", "GSSAPI", "PLAIN\tLOGIN SCRAM-SHA-256"};
  for (const char *mechanism : denied) {
    if (mailsasl_mechanism_allowed(mechanism)) return EXIT_FAILURE;
  }
  for (const char *mechanism : allowed) {
    if (!mailsasl_mechanism_allowed(mechanism)) return EXIT_FAILURE;
  }
  if (mailsasl_mechanism_allowed(NULL)) return EXIT_FAILURE;
  std::cout << "DIGEST-MD5 denied before SASL on all protocols; other mechanisms retained\n";
  return EXIT_SUCCESS;
}
