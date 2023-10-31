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

#include <tchar.h>

#ifdef OPENVPN_VERSION_RESOURCE
#include "syshead.h"
struct
{
    DWORD config_mode;
    TCHAR config_path[MAX_PATH];
} o;

#else
#include <windows.h>
#include "main.h"
#include "options.h"
extern options_t o;
#endif

#define NOHOOK
#include "hook.h"

#define DATA_MAX_SIZE 65536

__declspec( thread ) int no_hook = 0;

const _HKEY _HKEY_LOCAL_MACHINE = &(__HKEY){ HKEY_LOCAL_MACHINE, _T("HKEY_LOCAL_MACHINE"), 0 };
const _HKEY _HKEY_CURRENT_USER = &(__HKEY){ HKEY_CURRENT_USER, _T("HKEY_CURRENT_USER"), 0 };

int
hex2bin(const TCHAR *data, int datalen, BYTE *buf, int buflen)
{
    int m, n;
    BYTE hex, odd = 0;
    TCHAR *p;
    TCHAR dict[] = _T("0123456789ABCDEFabcdef");
    for (m = 0, n = 0; m < datalen && n < buflen; m++)
    {
        if (data[m] == _T('\0'))
        {
            break;
        }
        if (data[m] == _T(' ') || data[m] == _T(','))
        {
            continue;
        }
        p = _tcschr(dict, data[m]);
        if ((p = _tcschr(dict, data[m])))
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

static __inline void DbgPrintf(const TCHAR *fmt, ...)
{
    TCHAR buf[1024] = { 0 };
    va_list ap;
    va_start(ap, fmt);
    _vsntprintf(buf, _countof(buf) - 1, fmt, ap);
    va_end(ap);
    OutputDebugString(buf);
}

DWORD
InitConfigMode()
{
    HKEY regkey;
    DWORD dwType = 0, len = MAX_PATH;
    TCHAR buf[MAX_PATH], buf2[MAX_PATH];
    GetInstallPath(buf, _countof(buf));
    GetConfigPath(o.config_path, _countof(o.config_path));
    if (_taccess(o.config_path, 0) != 0)
    {
        if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\OpenVPN"), 0, KEY_READ, &regkey) == ERROR_SUCCESS)
        {
            if(RegQueryValueEx(regkey, _T(""), NULL, &dwType, (BYTE *) buf2, &len) == ERROR_SUCCESS)
            {
                len = _tcslen(buf2);
                if (buf2[len - 1] == _T('\\'))
                {
                    buf2[len - 1] = _T('\0');
                }
                if(dwType == REG_SZ && _tcsicmp(buf, buf2) == 0)
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
    GetPrivateProfileString(_T("HKEY_LOCAL_MACHINE\\SOFTWARE\\OpenVPN"), _T("@"), NULL, buf2, _countof(buf2), o.config_path);
    if(_tcsicmp(buf, buf2) != 0)
    {
        WritePrivateProfileString(_T("HKEY_LOCAL_MACHINE\\SOFTWARE\\OpenVPN"), _T("@"), buf, o.config_path);
    }
#endif
    return o.config_mode;
}

DWORD
GetConfigPath(LPTSTR lpPath,  DWORD dwSize)
{
    GetModuleFileName(NULL, lpPath, dwSize);
    *_tcsrchr(lpPath, _T('\\')) = _T('\0');
    _tcsncat(lpPath, _T("\\openvpn.cfg"), dwSize);
    return _tcslen(lpPath);
}

DWORD
GetInstallPath(LPTSTR lpPath, DWORD dwSize)
{
    GetModuleFileName(NULL, lpPath, dwSize);
    *_tcsrchr(lpPath, _T('\\')) = _T('\0');
    TCHAR *p = _tcsrchr(lpPath, _T('\\'));
    if (!_tcsnicmp(p, _T("\\bin"), _countof(_T("\\bin"))))
    {
        *p = _T('\0');
    }
    return _tcslen(lpPath);
}

DWORD
BuildPath(LPTSTR lpPath, DWORD dwSize, LPCTSTR lpPath1, LPCTSTR lpPath2)
{
    DWORD len = _tcslen(lpPath1);
    _tcsncpy(lpPath, lpPath1, dwSize);
    lpPath[dwSize - 1] = _T('\0');
    if (lpPath[len -1] == _T('\\') && (!lpPath2 || lpPath2[0] == _T('\\')))
    {
        len--;
        lpPath[len] = _T('\0');
    }
    if (!lpPath2)
    {
        return len;
    }
    if (lpPath[len -1] != _T('\\') && lpPath2[0] != _T('\\'))
    {
        lpPath[len] = _T('\\');
        lpPath[len +1] = _T('\0');
        len++;
    }
    _tcsncat(lpPath, lpPath2, dwSize - len);
    len = _tcslen(lpPath);
    if (lpPath[len -1] == _T('\\'))
    {
        lpPath[len -1] = _T('\0');
    }
    return _tcslen(lpPath);
}

const struct {
    DWORD dwtype;
    DWORD dwpos;
    TCHAR ctype[8];
} regtype[] = {
    {REG_DWORD, 6, _T("dword:")},
    {REG_QWORD, 7, _T("hex(b):")},
    {REG_BINARY, 4, _T("hex:")},
    {REG_MULTI_SZ, 7, _T("hex(7):")},
    {REG_EXPAND_SZ, 7, _T("hex(2):")},
    {REG_SZ, 0, _T("")},
};

LSTATUS
ConfigGet(LPCTSTR lpSubkey, LPCTSTR lpValueName, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    DWORD len = 0, pos = 0, i = 0;
    LSTATUS status = ERROR_SUCCESS;
    LPTSTR buff = malloc(DATA_MAX_SIZE * sizeof(TCHAR));
    if (!buff)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (!lpValueName || _tcslen(lpValueName) ==0)
    {
        lpValueName = _T("@");
    }
    GetPrivateProfileString(lpSubkey, lpValueName, NULL, buff, DATA_MAX_SIZE, o.config_path);
    len = _tcslen(buff);
    if (len ==0)
    {
        GetPrivateProfileString(lpSubkey, lpValueName, _T("1"), buff, DATA_MAX_SIZE, o.config_path);
        if (_tcslen(buff) == 1)
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
        if (_tcsncmp(buff, regtype[i].ctype,  regtype[i].dwpos) == 0)
        {
            pos = regtype[i].dwpos;
            *lpType = regtype[i].dwtype;
            break;
        }
    }
    if (*lpType == REG_SZ)
    {
        _tcsncpy((LPTSTR)lpData, buff, len);
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
_RegOpenKeyEx(_HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, _PHKEY phkResult)
{
    if (!(*phkResult = malloc(sizeof(__HKEY))))
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if (o.config_mode == 0 || no_hook)
    {
        return RegOpenKeyEx(hKey->regkey, lpSubKey, ulOptions, samDesired, &(*phkResult)->regkey);
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
_RegGetValue(_HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
{
    TCHAR subkey[MAX_PATH];
    DWORD dwType;
    LSTATUS status = ERROR_SUCCESS;
    if (o.config_mode == 0 || no_hook)
    {
        return RegGetValue(hKey->regkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
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

#endif /* ifdef _WIN32 */
