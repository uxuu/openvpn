/*
 *  OpenVPN-GUI -- A Windows GUI for OpenVPN.
 *
 *  Copyright (C) 2004 Mathias Sundman <mathias@nilings.se>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef _WIN32
#ifndef HOOK_H
#define HOOK_H

typedef struct {
    HKEY regkey;
    TCHAR subkey[MAX_PATH];
    DWORD dwFlags;
} __HKEY, *_HKEY, **_PHKEY;

extern const _HKEY _HKEY_LOCAL_MACHINE;
extern const _HKEY _HKEY_CURRENT_USER;
extern __declspec( thread ) int no_hook;

#ifdef UNICODE
#define GetConfigPath GetConfigPathW
#define GetInstallPath GetInstallPathW
#define _RegOpenKeyEx _RegOpenKeyExW
#define _RegGetValue _RegGetValueW
#else
#define GetConfigPath GetConfigPathA
#define GetInstallPath GetInstallPathA
#define _RegOpenKeyEx _RegOpenKeyExA
#define _RegGetValue _RegGetValueA
#endif // !UNICODE


DWORD InitConfigMode();

DWORD GetConfigPathA(LPSTR lpPath,  DWORD dwSize);
DWORD GetConfigPathW(LPWSTR lpPath,  DWORD dwSize);

DWORD GetInstallPathA(LPSTR lpPath, DWORD dwSize);
DWORD GetInstallPathW(LPWSTR lpPath, DWORD dwSize);

LSTATUS _RegOpenKeyExA(_HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, _PHKEY phkResult);
LSTATUS _RegOpenKeyExW(_HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, _PHKEY phkResult);

LSTATUS _RegGetValueA(_HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);
LSTATUS _RegGetValueW(_HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);

LSTATUS _RegCloseKey(_HKEY hKey);

#ifndef NOHOOK

#define HKEY _HKEY
#define PHKEY _PHKEY

#undef HKEY_LOCAL_MACHINE
#define HKEY_LOCAL_MACHINE _HKEY_LOCAL_MACHINE
#undef HKEY_CURRENT_USER
#define HKEY_CURRENT_USER _HKEY_CURRENT_USER

#define RegOpenKeyExW _RegOpenKeyExW
#define RegGetValueW _RegGetValueW

#define RegOpenKeyExA _RegOpenKeyExA
#define RegGetValueA _RegGetValueA

#define RegCloseKey _RegCloseKey

#endif /* ifndef NOHOOK */
#endif /* ifndef HOOK_H */
#endif /* ifdef _WIN32 */
