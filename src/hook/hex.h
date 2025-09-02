#ifndef HOOK_HEX_H
#define HOOK_HEX_H

int bin2hex(const BYTE *data, const int datalen, LPWSTR buf, int buflen,
               int group_size, const WCHAR sp, int line_bytes);
int hex2bin(const LPWSTR buf, const int buflen, BYTE *data, int datalen);

#endif  // HOOK_HEX_H
