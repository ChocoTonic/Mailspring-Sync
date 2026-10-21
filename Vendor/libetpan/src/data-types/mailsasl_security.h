#ifndef MAILSASL_SECURITY_H
#define MAILSASL_SECURITY_H

/* Reject DIGEST-MD5 on every platform: system SASL plugins may not contain
 * the CVE-2026-107161 quoted-challenge allocation fix. Other mechanisms
 * remain available. Treat SASL mechanism lists as whitespace-delimited. */
static int mailsasl_mechanism_allowed(const char *mechanisms)
{
  const char blocked[] = "DIGEST-MD5";
  if (mechanisms == 0) return 0;
  while (*mechanisms) {
    unsigned length = 0;
    int matches = 1;
    while (*mechanisms == ' ' || *mechanisms == '\t' || *mechanisms == '\r' || *mechanisms == '\n') mechanisms++;
    if (!*mechanisms) break;
    while (*mechanisms && *mechanisms != ' ' && *mechanisms != '\t' && *mechanisms != '\r' && *mechanisms != '\n') {
      unsigned char ch = (unsigned char)*mechanisms++;
      if (ch >= 'a' && ch <= 'z') ch -= 'a' - 'A';
      if (length >= sizeof(blocked) - 1 || ch != blocked[length]) matches = 0;
      length++;
    }
    if (matches && length == sizeof(blocked) - 1) return 0;
  }
  return 1;
}
#endif
