/*
 *  OpenVPN-GUI -- A Windows GUI for OpenVPN.
 *
 *  Copyright (C) 2004 Mathias Sundman <mathias@nilings.se>
 *                2016 Selva Nair <selva.nair@gmail.com>
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
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef _WIN32

#ifdef OPENVPN_VERSION_RESOURCE
#include "syshead.h"
struct
{
    DWORD config_mode;
    WCHAR config_path[MAX_PATH];
} o;

#else
#include <windows.h>
#include "main.h"
#include "options.h"
extern options_t o;
#endif

#define NOHOOK
#include "hook.h"
#include "common.h"
#define DATA_MAX_SIZE 65536

__declspec( thread ) int no_hook = 0;

const _HKEY _HKEY_LOCAL_MACHINE = &(__HKEY){ HKEY_LOCAL_MACHINE, L"HKEY_LOCAL_MACHINE", 0 };
const _HKEY _HKEY_CURRENT_USER = &(__HKEY){ HKEY_CURRENT_USER, L"HKEY_CURRENT_USER", 0 };

int
bin2hex(const BYTE *data, int datalen, WCHAR *buf, int buflen)
{
    int m, n;
    WCHAR dict[] = L"0123456789ABCDEF";
    int buflen2 = buflen >> 1 << 1;
    if (buflen == buflen2)
    {
        buflen2 = buflen - 2;
    }
    for (m = 0, n = 0; m < datalen && n < buflen2; m++, n++)
    {
        buf[n] = dict[data[m] >> 4 & 0x0F];
        buf[++n] = dict[data[m] & 0x0F];
    }
    buf[n] = L'\0';
    return n;
}

int
hex2bin(const WCHAR *data, int datalen, BYTE *buf, int buflen)
{
    int m, n;
    BYTE hex, odd = 0;
    WCHAR *p;
    WCHAR dict[] = L"0123456789ABCDEFabcdef";
    for (m = 0, n = 0; m < datalen && n < buflen; m++)
    {
        if (data[m] == L'\0')
        {
            break;
        }
        if (data[m] == L' ' || data[m] == L',')
        {
            continue;
        }
        p = wcschr(dict, data[m]);
        if ((p = wcschr(dict, data[m])))
        {
            hex = p - dict;
        }
        else
        {
            continue;
        }
        if (hex > 0x0F)
        {
            hex -= 6;
        }
        if (odd)
        {
            buf[n++] |= hex;
        }
        else
        {
            buf[n] = hex << 4;
        }
        odd = !odd;
    }
    return n;
}

DWORD
InitConfigMode()
{
    HKEY regkey;
    DWORD dwType = 0, len = MAX_PATH;
    WCHAR buf[MAX_PATH], buf2[MAX_PATH];
    GetInstallPath(buf, _countof(buf));
    GetConfigPath(o.config_path, _countof(o.config_path));
    if (_waccess(o.config_path, 0) == 0)
    {
        if(RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\OpenVPN", 0, KEY_READ, &regkey) == ERROR_SUCCESS)
        {
            if(RegQueryValueExW(regkey, L"", NULL, &dwType, (BYTE *) buf2, &len) == ERROR_SUCCESS)
            {
                if(dwType == REG_SZ && _wcsicmp(buf, buf2) == 0)
                {
                    RegCloseKey(regkey);
                    return o.config_mode;
                }
            }
            RegCloseKey(regkey);
        }
    }
    o.config_mode = 1;

#ifndef OPENVPN_VERSION_RESOURCE
    GetPrivateProfileStringW(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\OpenVPN", L"@", NULL, buf2, _countof(buf2), o.config_path);
    if(_wcsicmp(buf, buf2) != 0)
    {
        WritePrivateProfileStringW(L"HKEY_LOCAL_MACHINE\\SOFTWARE\\OpenVPN", L"@", buf, o.config_path);
    }
#endif
    return o.config_mode;
}

DWORD
GetConfigPath(LPWSTR lpPath,  DWORD dwSize)
{
    GetModuleFileNameW(NULL, lpPath, dwSize);
    *wcsrchr(lpPath, L'\\') = L'\0';
    wcsncat(lpPath, L"\\openvpn.cfg", dwSize);
    return wcslen(lpPath);
}

DWORD
GetInstallPath(LPWSTR lpPath, DWORD dwSize)
{
    GetModuleFileNameW(NULL, lpPath, dwSize);
    *wcsrchr(lpPath, L'\\') = L'\0';
    WCHAR *p = wcsrchr(lpPath, L'\\');
    if (!_wcsnicmp(p, L"\\bin", _countof(L"\\bin")))
    {
        *p = L'\0';
    }
    return wcslen(lpPath);
}

DWORD
GetInstallBinPath(LPWSTR lpPath, DWORD dwSize)
{
    GetModuleFileNameW(NULL, lpPath, dwSize);
    *wcsrchr(lpPath, L'\\') = L'\0';
    return wcslen(lpPath);
}

DWORD
BuildPath(LPWSTR lpPath, DWORD dwSize, LPCWSTR lpPath1, LPCWSTR lpPath2)
{
    DWORD len = wcslen(lpPath1);
    wcsncpy(lpPath, lpPath1, dwSize);
    lpPath[dwSize - 1] = L'\0';
    if (lpPath[len -1] == L'\\' && (!lpPath2 || lpPath2[0] == L'\\'))
    {
        len--;
        lpPath[len] = L'\0';
    }
    if (!lpPath2)
    {
        return len;
    }
    if (lpPath[len -1] != L'\\' && lpPath2[0] != L'\\')
    {
        lpPath[len] = L'\\';
        lpPath[len +1] = L'\0';
        len++;
    }
    wcsncat(lpPath, lpPath2, dwSize - len);
    len = wcslen(lpPath);
    if (lpPath[len -1] == L'\\')
    {
        lpPath[len -1] = L'\0';
    }
    return wcslen(lpPath);
}

const struct {
    DWORD dwtype;
    DWORD dwpos;
    WCHAR ctype[8];
} regtype[] = {
    {REG_DWORD, 6, L"dword:"},
    {REG_QWORD, 7, L"hex(b):"},
    {REG_BINARY, 4, L"hex:"},
    {REG_MULTI_SZ, 7, L"hex(7):"},
    {REG_EXPAND_SZ, 7, L"hex(2):"},
    {REG_SZ, 0, L""},
};

LSTATUS
ConfigGet(LPCWSTR lpSubkey, LPCWSTR lpValueName, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    DWORD len = 0, pos = 0, i = 0;
    LSTATUS status = ERROR_SUCCESS;
    LPWSTR buff = malloc(DATA_MAX_SIZE * sizeof(WCHAR));
    if (!buff)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (!lpValueName || wcslen(lpValueName) ==0)
    {
        lpValueName = L"@";
    }
    GetPrivateProfileStringW(lpSubkey, lpValueName, NULL, buff, DATA_MAX_SIZE, o.config_path);
    len = wcslen(buff);
    if (len ==0)
    {
        GetPrivateProfileStringW(lpSubkey, lpValueName, L"1", buff, DATA_MAX_SIZE, o.config_path);
        if (wcslen(buff) == 1)
        {
            status = ERROR_CANTREAD;
        }
    }
    if (!lpcbData)
    {
        free(buff);
        return status;
    }

    for (i = 0; i < _countof(regtype); i++)
    {
        if (wcsncmp(buff, regtype[i].ctype,  regtype[i].dwpos) == 0)
        {
            pos = regtype[i].dwpos;
            *lpType = regtype[i].dwtype;
            break;
        }
    }
    if (*lpType == REG_SZ)
    {
        wcsncpy((LPWSTR)lpData, buff, len);
        *lpcbData = (len +1) * sizeof(buff[0]);
        free(buff);
        return status;
    }
    len = hex2bin(buff + pos, len - pos, lpData, *lpcbData);
    switch (*lpType)
    {
        case REG_DWORD:
            *lpcbData = 4;
            *(LPDWORD)lpData = ntohl(*(LPDWORD)lpData);
            break;

        case REG_QWORD:
            *lpcbData = 8;
            break;

        case REG_BINARY:
        case REG_MULTI_SZ:
        case REG_EXPAND_SZ:
        default:
            *lpcbData = len;
            break;
    }
    free(buff);
    return status;
}

LSTATUS
ConfigSet(LPCWSTR lpSubkey, LPCWSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData)
{
    LPCVOID p = lpData;
    DWORD dwData;
    DWORD pos = 0, i = 0;
    LPWSTR buff = malloc(DATA_MAX_SIZE * sizeof(WCHAR));
    if (!buff)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (!lpValueName || wcslen(lpValueName) ==0)
    {
        lpValueName = L"@";
    }
    for (i = 0; i < _countof(regtype); i++)
    {
        if (regtype[i].dwtype == dwType)
        {
            pos = regtype[i].dwpos;
            wcsncpy(buff, regtype[i].ctype, pos);
            buff[DATA_MAX_SIZE -1] = L'\0';
            break;
        }
    }
    switch (dwType)
    {
        case REG_DWORD:
            dwData = htonl(*(LPDWORD)lpData);
            p = (BYTE *)&dwData;
            break;

        case REG_QWORD:
        case REG_BINARY:
            break;

        case REG_MULTI_SZ:
        case REG_EXPAND_SZ:
            cbData++;
            break;

        case REG_SZ:
        default:
            WritePrivateProfileStringW(lpSubkey, lpValueName, lpData, o.config_path);
            free(buff);
            return ERROR_SUCCESS;
    }
    bin2hex(p, cbData, buff + pos, DATA_MAX_SIZE);
    WritePrivateProfileStringW(lpSubkey, lpValueName, buff, o.config_path);
    free(buff);
    return ERROR_SUCCESS;
}

DWORD
Reg2RRF(DWORD dwType)
{
    switch (dwType)
    {
        case REG_SZ: return RRF_RT_REG_SZ;

        case REG_BINARY: return RRF_RT_REG_BINARY;

        case REG_DWORD: return RRF_RT_REG_DWORD;

        case REG_QWORD: return RRF_RT_REG_QWORD;

        case REG_MULTI_SZ: return RRF_RT_REG_MULTI_SZ;

        case REG_EXPAND_SZ: return RRF_RT_REG_EXPAND_SZ;

        default: return RRF_RT_REG_NONE;
    }
}

LSTATUS
_RegCreateKeyExW(
    _HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD dwReserved,
    LPWSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _PHKEY phkResult,
    LPDWORD lpdwDisposition
    )
{
    if (!(*phkResult = malloc(sizeof(__HKEY))))
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (o.config_mode == 0 || no_hook)
    {
        return RegCreateKeyExW(hKey->regkey,
                               lpSubKey,
                               dwReserved,
                               lpClass,
                               dwOptions,
                               samDesired,
                               lpSecurityAttributes,
                               &(*phkResult)->regkey,
                               lpdwDisposition);
    }
    BuildPath((*phkResult)->subkey, _countof((*phkResult)->subkey), hKey->subkey, lpSubKey);
    return ERROR_SUCCESS;
}

LSTATUS
_RegOpenKeyExW(_HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, _PHKEY phkResult)
{
    if (!(*phkResult = malloc(sizeof(__HKEY))))
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (o.config_mode == 0 || no_hook)
    {
        return RegOpenKeyExW(hKey->regkey, lpSubKey, ulOptions, samDesired, &(*phkResult)->regkey);
    }
    BuildPath((*phkResult)->subkey, _countof((*phkResult)->subkey), hKey->subkey, lpSubKey);
    return ERROR_SUCCESS;
}

LSTATUS
_RegCloseKey(_HKEY hKey)
{
    LSTATUS status = ERROR_SUCCESS;
    if (o.config_mode == 0 || no_hook)
    {
        status = RegCloseKey(hKey->regkey);
        free(hKey);
        return status;
    }
    return ERROR_SUCCESS;
}

LSTATUS
_RegQueryValueExW(_HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    if (o.config_mode == 0 || no_hook)
    {
        return RegQueryValueExW(hKey->regkey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    }
    return ConfigGet(hKey->subkey, lpValueName, lpType, lpData, lpcbData);
}

LSTATUS
_RegGetValueW(_HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
{
    WCHAR subkey[MAX_PATH];
    DWORD dwType;
    LSTATUS status = ERROR_SUCCESS;
    if (o.config_mode == 0 || no_hook)
    {
        return RegGetValueW(hKey->regkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
    }
    BuildPath(subkey, _countof(subkey), hKey->subkey, lpSubKey);
    status = ConfigGet(subkey, lpValue, &dwType, pvData, pcbData);
    if (pdwType)
    {
        *pdwType = dwType;
    }
    if (Reg2RRF(dwType) != dwFlags)
    {
        return ERROR_CANTREAD;
    }
    return status;
}

LSTATUS
_RegSetValueExW(_HKEY hKey, LPCWSTR lpValueName, DWORD dwReserved, DWORD dwType, const BYTE *lpData, DWORD cbData)
{
    if (o.config_mode == 0 || no_hook)
    {
        return RegSetValueExW(hKey->regkey, lpValueName, dwReserved, dwType, lpData, cbData);
    }
    return ConfigSet(hKey->subkey, lpValueName, dwType, lpData, cbData);
}

LSTATUS
_RegDeleteKeyW(_HKEY hKey, LPCWSTR lpSubKey)
{
    WCHAR subkey[MAX_PATH];
    if (o.config_mode == 0 || no_hook)
    {
        return RegDeleteKeyW(hKey->regkey, lpSubKey);
    }
    BuildPath(subkey, _countof(subkey), hKey->subkey, lpSubKey);
    WritePrivateProfileSectionW(subkey, NULL, o.config_path);
    return ERROR_SUCCESS;
}


LSTATUS
_RegDeleteValueW(_HKEY hKey, LPCWSTR lpValueName)
{
    if (o.config_mode == 0 || no_hook)
    {
        return RegDeleteValueW(hKey->regkey, lpValueName);
    }
    WritePrivateProfileStringW(hKey->subkey, lpValueName, NULL, o.config_path);
    return ERROR_SUCCESS;
}

LSTATUS
_RegDeleteTreeW(_HKEY hKey, LPCWSTR lpSubKey)
{
    WCHAR subkey[MAX_PATH];
    if (o.config_mode == 0 || no_hook)
    {
        RegDeleteTreeW(hKey->regkey, lpSubKey);
    }
    BuildPath(subkey, _countof(subkey), hKey->subkey, lpSubKey);
    WritePrivateProfileSectionW(subkey, NULL, o.config_path);
    return ERROR_SUCCESS;
}

LSTATUS
_RegDeleteKeyValueW(_HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName)
{
    WCHAR subkey[MAX_PATH];
    if (o.config_mode == 0 || no_hook)
    {
        return RegDeleteKeyValueW(hKey->regkey, lpSubKey, lpValueName);
    }
    BuildPath(subkey, _countof(subkey), hKey->subkey, lpSubKey);
    WritePrivateProfileStringW(subkey, lpValueName, NULL, o.config_path);
    return ERROR_SUCCESS;
}

LSTATUS
_RegSetKeyValueW(_HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData)
{
    WCHAR subkey[MAX_PATH];
    if (o.config_mode == 0 || no_hook)
    {
        return RegSetKeyValueW(hKey->regkey, lpSubKey, lpValueName, dwType, lpData, cbData);
    }
    BuildPath(subkey, _countof(subkey), hKey->subkey, lpSubKey);
    return ConfigSet(subkey, lpValueName, dwType, lpData, cbData);
}

LSTATUS
_RegCopyTreeW(_HKEY hKeySrc, LPCWSTR lpSubKey, _HKEY hKeyDest)
{
    WCHAR subkeySrc[MAX_PATH];
    WCHAR subkeyDest[MAX_PATH];
    LPWSTR buff;
    if (o.config_mode == 0 || no_hook)
    {
        return RegCopyTreeW(hKeySrc->regkey, lpSubKey, hKeyDest->regkey);
    }
    buff = malloc(DATA_MAX_SIZE * sizeof(WCHAR));
    if (!buff)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    BuildPath(subkeySrc, _countof(subkeySrc), hKeySrc->subkey, lpSubKey);
    BuildPath(subkeyDest, _countof(subkeyDest), hKeyDest->subkey, lpSubKey);
    GetPrivateProfileSectionW(subkeySrc, buff, DATA_MAX_SIZE, o.config_path);
    WritePrivateProfileSectionW(subkeyDest, buff, o.config_path);
    free(buff);
    return ERROR_SUCCESS;
}
#endif /* ifdef _WIN32 */
