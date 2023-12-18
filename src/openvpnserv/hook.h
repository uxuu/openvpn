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
    WCHAR subkey[MAX_PATH];
    DWORD dwFlags;
} __HKEY, *_HKEY, **_PHKEY;

extern const _HKEY _HKEY_LOCAL_MACHINE;
extern const _HKEY _HKEY_CURRENT_USER;
extern __declspec( thread ) int no_hook;

LSTATUS _RegCreateKeyExW(
    _HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD Reserved,
    LPWSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _PHKEY phkResult,
    LPDWORD lpdwDisposition
    );

DWORD InitConfigMode();

DWORD GetConfigPath(LPWSTR lpPath,  DWORD dwSize);

DWORD GetInstallPath(LPWSTR lpPath, DWORD dwSize);

DWORD GetInstallBinPath(LPWSTR lpPath, DWORD dwSize);

LSTATUS _RegOpenKeyExW(_HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, _PHKEY phkResult);

LSTATUS _RegCloseKey(_HKEY hKey);

LSTATUS _RegQueryValueExW(_HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);

LSTATUS _RegGetValueW(_HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);

LSTATUS _RegSetValueExW(_HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);

LSTATUS _RegDeleteKeyW(_HKEY hKey, LPCWSTR lpSubKey);

LSTATUS _RegDeleteValueW(_HKEY hKey, LPCWSTR lpValueName);

LSTATUS _RegDeleteTreeW(_HKEY hKey, LPCWSTR lpSubKey);

LSTATUS _RegDeleteKeyValueW(_HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName);

LSTATUS _RegSetKeyValueW(_HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData);

LSTATUS _RegCopyTreeW(_HKEY hKeySrc, LPCWSTR lpSubKey, _HKEY hKeyDest);

#ifndef NOHOOK

#define HKEY _HKEY
#define PHKEY _PHKEY

#undef HKEY_LOCAL_MACHINE
#define HKEY_LOCAL_MACHINE _HKEY_LOCAL_MACHINE
#undef HKEY_CURRENT_USER
#define HKEY_CURRENT_USER _HKEY_CURRENT_USER

#define RegOpenKeyExW _RegOpenKeyExW
#define RegCloseKey _RegCloseKey
#define RegCreateKeyExW _RegCreateKeyExW
#define RegQueryValueExW _RegQueryValueExW
#define RegGetValueW _RegGetValueW
#define RegSetValueExW _RegSetValueExW
#define RegDeleteKeyW _RegDeleteKeyW
#define RegDeleteValueW _RegDeleteValueW
#define RegDeleteTreeW _RegDeleteTreeW
#define RegDeleteKeyValueW _RegDeleteKeyValueW
#define RegSetKeyValueW _RegSetKeyValueW
#define RegCopyTreeW _RegCopyTreeW

#endif /* ifndef NOHOOK */
#endif /* ifndef HOOK_H */
#endif /* ifdef _WIN32 */
