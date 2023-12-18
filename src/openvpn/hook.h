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
#define _RegOpenKeyEx _RegOpenKeyExW
#define _RegCreateKeyEx _RegCreateKeyExW
#define _RegQueryValueEx _RegQueryValueExW
#define _RegGetValue _RegGetValueW
#define _RegSetValueEx _RegSetValueExW
#define _RegDeleteKey _RegDeleteKeyW
#define _RegDeleteValue _RegDeleteValueW
#define _RegDeleteTree _RegDeleteTreeW
#define _RegDeleteKeyValue _RegDeleteKeyValueW
#define _RegSetKeyValue _RegSetKeyValueW
#define _RegCopyTree _RegCopyTreeW
#else
#define _RegOpenKeyEx _RegOpenKeyExA
#define _RegCreateKeyEx _RegCreateKeyExA
#define _RegQueryValueEx _RegQueryValueExA
#define _RegGetValue _RegGetValueA
#define _RegSetValueEx _RegSetValueExA
#define _RegDeleteKey _RegDeleteKeyA
#define _RegDeleteValue _RegDeleteValueA
#define _RegDeleteTree _RegDeleteTreeA
#define _RegDeleteKeyValue _RegDeleteKeyValueA
#define _RegSetKeyValue _RegSetKeyValueA
#define _RegCopyTree _RegCopyTreeA
#endif // !UNICODE


DWORD InitConfigMode();

DWORD GetConfigPath(LPTSTR lpPath,  DWORD dwSize);

DWORD GetInstallPath(LPTSTR lpPath, DWORD dwSize);

DWORD GetInstallBinPath(LPTSTR lpPath, DWORD dwSize);

LSTATUS _RegOpenKeyEx(_HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, _PHKEY phkResult);

LSTATUS _RegCreateKeyEx(_HKEY hKey, LPCTSTR lpSubKey, DWORD Reserved, LPTSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, _PHKEY phkResult, LPDWORD lpdwDisposition);

LSTATUS _RegQueryValueEx(_HKEY hKey, LPCTSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);

LSTATUS _RegGetValue(_HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);

LSTATUS _RegSetValueEx(_HKEY hKey, LPCTSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);

LSTATUS _RegDeleteKey(_HKEY hKey, LPCTSTR lpSubKey);

LSTATUS _RegDeleteValue(_HKEY hKey, LPCTSTR lpValueName);

LSTATUS _RegDeleteTree(_HKEY hKey, LPCTSTR lpSubKey);

LSTATUS _RegDeleteKeyValue(_HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValueName);

LSTATUS _RegSetKeyValue(_HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData);

LSTATUS _RegCopyTree(_HKEY hKeySrc, LPCTSTR lpSubKey, _HKEY hKeyDest);

LSTATUS _RegCloseKey(_HKEY hKey);

#ifndef NOHOOK

#define HKEY _HKEY
#define PHKEY _PHKEY

#undef HKEY_LOCAL_MACHINE
#define HKEY_LOCAL_MACHINE _HKEY_LOCAL_MACHINE
#undef HKEY_CURRENT_USER
#define HKEY_CURRENT_USER _HKEY_CURRENT_USER

#define RegOpenKeyExW _RegOpenKeyExW
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

#define RegOpenKeyExA _RegOpenKeyExA
#define RegCreateKeyExA _RegCreateKeyExA
#define RegQueryValueExA _RegQueryValueExA
#define RegGetValueA _RegGetValueA
#define RegSetValueExA _RegSetValueExA
#define RegDeleteKeyA _RegDeleteKeyA
#define RegDeleteValueA _RegDeleteValueA
#define RegDeleteTreeA _RegDeleteTreeA
#define RegDeleteKeyValueA _RegDeleteKeyValueA
#define RegSetKeyValueA _RegSetKeyValueA
#define RegCopyTreeA _RegCopyTreeA

#define RegCloseKey _RegCloseKey

#endif /* ifndef NOHOOK */
#endif /* ifndef HOOK_H */
#endif /* ifdef _WIN32 */
