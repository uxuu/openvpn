#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef _WIN32

#include <stdlib.h>
#include <tchar.h>
#include <windows.h>
#include <winsock.h>

#define HOOK_REG_NOHOOK
#include "hex.h"
#include "reghook.h"

/* 配置模式枚举 */
enum
{
    HOOK_CONFIG_REG = 0,  /* 使用Windows注册表 */
    HOOK_CONFIG_INI = 1   /* 使用INI文件 */
};

DWORD config_mode = HOOK_CONFIG_REG;  /* 当前配置模式 */
static WCHAR config_path[MAX_PATH];          /* 配置文件路径 */

/* 注册表键值类型信息结构体 */
typedef struct {
    const DWORD dwtype;     /* 注册表值类型 */
    const DWORD dwpos;      /* 值前缀的长度 */
    const WCHAR ctype[8];   /* 值前缀字符串 */
} KEY_INFO;

/* 不同注册表值类型的信息定义 */
static const KEY_INFO key_infos[] = {
    {REG_DWORD, 6, L"dword:"},
    {REG_QWORD, 7, L"hex(b):"},
    {REG_BINARY, 4, L"hex:"},
    {REG_MULTI_SZ, 7, L"hex(7):"},
    {REG_EXPAND_SZ, 7, L"hex(2):"},
    {REG_SZ, 0, L""},
    {REG_NONE, 0, L""},
};

#define DATA_MAX_SIZE 65536  /* 数据缓冲区最大大小 */

/* 预定义的注册表根键 */
const HOOK_HKEY HOOK_HKCR = &(_HOOK_HKEY){ HKEY_CLASSES_ROOT, L"HKCR", 0 };
const HOOK_HKEY HOOK_HKLM = &(_HOOK_HKEY){ HKEY_LOCAL_MACHINE, L"HKLM", 0 };
const HOOK_HKEY HOOK_HKCU = &(_HOOK_HKEY){ HKEY_CURRENT_USER, L"HKCU", 0 };

/*
 * 根据注册表值类型获取对应的KEY_INFO信息
 */
static KEY_INFO HookGetKeyInfoForType(DWORD dwType)
{
    for (int i = 0; i < _countof(key_infos); i++)
    {
        if (dwType == key_infos[i].dwtype)
        {
            return key_infos[i];
        }
    }
    /* 返回默认值(REG_NONE) */
    return key_infos[_countof(key_infos) - 1];
}

/*
 * 根据数据内容确定注册表值类型
 */
static KEY_INFO HookGetKeyInfoForData(LPCWSTR lpData, DWORD dwSize)
{
    if (!lpData || dwSize == 0)
        return key_infos[_countof(key_infos) - 1];

    for (int i = 0; i < _countof(key_infos); i++)
    {
        if (dwSize >= key_infos[i].dwpos &&
            wcsncmp(lpData, key_infos[i].ctype, key_infos[i].dwpos) == 0)
        {
            return key_infos[i];
        }
    }
    /* 返回默认值(REG_NONE) */
    return key_infos[_countof(key_infos) - 1];
}

/*
 * 获取当前模块所在的bin目录路径
 */
DWORD GetInstallBinPath(LPWSTR lpPath, DWORD dwSize)
{
    GetModuleFileNameW(NULL, lpPath, dwSize);
    *wcsrchr(lpPath, L'\\') = L'\0';
    return wcslen(lpPath);
}

/*
 * 获取安装目录路径（去掉bin部分）
 */
DWORD GetInstallPath(LPWSTR lpPath, DWORD dwSize)
{
    DWORD dwLength = GetInstallBinPath(lpPath, dwSize);
    LPWSTR p = wcsrchr(lpPath, L'\\');

    if (p && !wcsnicmp(p, L"\\bin", _countof(L"\\bin")))
    {
        *p = L'\0';
        dwLength = wcslen(lpPath);
    }

    return dwLength;
}

/*
 * 获取配置文件路径
 */
DWORD GetConfigPath(LPWSTR lpPath, DWORD dwSize)
{
    DWORD dwLength = GetInstallBinPath(lpPath, dwSize);
    wcsncat(lpPath, L"\\openvpn.cfg", dwSize - dwLength - 1);
    return wcslen(lpPath);
}

/*
 * 构建路径，正确处理路径分隔符
 */
static DWORD HookBuildPath(LPWSTR lpPath, DWORD dwSize, LPCWSTR lpPath1, LPCWSTR lpPath2)
{
    DWORD dwLength = wcslen(lpPath1);
    wcsncpy(lpPath, lpPath1, dwSize);
    lpPath[dwSize - 1] = L'\0';
    if (lpPath[dwLength -1] == L'\\' && (!lpPath2 || lpPath2[0] == L'\\'))
    {
        dwLength--;
        lpPath[dwLength] = L'\0';
    }
    if (!lpPath2)
    {
        return dwLength;
    }
    if (lpPath[dwLength -1] != L'\\' && lpPath2[0] != L'\\')
    {
        lpPath[dwLength] = L'\\';
        lpPath[dwLength +1] = L'\0';
        dwLength++;
    }
    wcsncat(lpPath, lpPath2, dwSize - dwLength);
    dwLength = wcslen(lpPath);
    if (lpPath[dwLength -1] == L'\\')
    {
        lpPath[dwLength -1] = L'\0';
    }
    return wcslen(lpPath);
}

static BOOL NeedHook(LPCWSTR lpSubkey)
{
    if (!lpSubkey)
        return TRUE;
    LPWSTR p = wcsrchr(lpSubkey, L'\\');
    if (!p)
        return TRUE;
    if (wcsnicmp(p, L"\\CredUI", wcslen(L"\\CredUI")) == 0)
        return  FALSE;
    if (wcsnicmp(p, L"\\Run", wcslen(L"\\Run")) == 0)
        return FALSE;
    return TRUE;
}

/*
 * 从配置文件中获取注册表值
 */
static LSTATUS HookGetRegValue(HOOK_HKEY hKey, LPCWSTR lpSubkey, LPCWSTR lpValueName,
                              LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    LSTATUS status = ERROR_SUCCESS;
    WCHAR section[MAX_PATH];
    LPWSTR pData = NULL;

    /* 分配内存 */
    if (!((pData = malloc(DATA_MAX_SIZE * sizeof(WCHAR)))) )
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    /* 处理默认值名称 */
    if (!lpValueName || wcslen(lpValueName) == 0)
    {
        lpValueName = L"@";
    }

    HookBuildPath(section, _countof(section), hKey->subkey, lpSubkey);

    /* 先尝试获取默认值为"*"的情况，再获取实际值 */
    DWORD dwLength = GetPrivateProfileStringW(section, lpValueName, L"*", pData, DATA_MAX_SIZE, config_path);
    if (dwLength == 1 && pData[0] != L'*')
    {
        if ((dwLength = GetPrivateProfileStringW(section, lpValueName, NULL, pData, DATA_MAX_SIZE, config_path)) == 0)
        {
            status = ERROR_CANTREAD;
        }
    }

    /* 如果只需要检查值是否存在 */
    if (!lpcbData)
    {
        free(pData);
        return status;
    }

    /* 确定值类型并解析数据 */
    if (lpType && lpData && *lpcbData > 0)
    {
        KEY_INFO key_info = HookGetKeyInfoForData(pData, dwLength);
        *lpType = key_info.dwtype;
        memset(lpData, 0, *lpcbData);

        switch (*lpType) {
            case REG_SZ:
                wcsncpy((LPWSTR)lpData, pData, *lpcbData / sizeof(WCHAR) - 1);
                *lpcbData = (wcslen((LPWSTR)lpData) + 1) * sizeof(WCHAR);
                break;
            case REG_DWORD:
                DWORD value = 0;
                hex2bin(pData + key_info.dwpos, dwLength - key_info.dwpos, (BYTE*)&value, sizeof(value));
                *(LPDWORD)lpData = ntohl(value);
                *lpcbData = sizeof(DWORD);
                break;
            case REG_QWORD:
                hex2bin(pData + key_info.dwpos, dwLength - key_info.dwpos, lpData, *lpcbData);
                *lpcbData = sizeof(ULONGLONG);
                break;

            case REG_BINARY:
            case REG_MULTI_SZ:
            case REG_EXPAND_SZ:
            default:
                *lpcbData = hex2bin(pData + key_info.dwpos, dwLength - key_info.dwpos, lpData, *lpcbData);
                break;
        }
    }

    free(pData);
    return status;
}

/*
 * 设置配置文件中的注册表值
 */
static LSTATUS HookSetRegValue(HOOK_HKEY hKey, LPCWSTR lpSubkey, LPCWSTR lpValueName,
                              DWORD dwType, LPCVOID lpData, DWORD cbData)
{
    WCHAR section[MAX_PATH];
    LPWSTR pData = NULL;

    /* 分配内存 */
    if (!((pData = (LPWSTR)malloc(DATA_MAX_SIZE * sizeof(WCHAR)))))
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    /* 处理默认值名称 */
    if (!lpValueName || wcslen(lpValueName) == 0)
    {
        lpValueName = L"@";
    }

    HookBuildPath(section, _countof(section), hKey->subkey, lpSubkey);
    KEY_INFO key_info = HookGetKeyInfoForType(dwType);

    /* 复制类型前缀 */
    if (key_info.dwpos > 0)
    {
        wcsncpy(pData, key_info.ctype, key_info.dwpos);
    }

    switch (dwType) {
        case REG_DWORD:
            /* DWORD需要网络字节序转换 */
            DWORD dwData = htonl(*(LPDWORD)lpData);
            bin2hex((BYTE *)&dwData, sizeof(DWORD), pData + key_info.dwpos, DATA_MAX_SIZE - key_info.dwpos, 0, 0, 0);
            WritePrivateProfileStringW(section, lpValueName, pData, config_path);
            break;

        case REG_QWORD:
        case REG_BINARY:
            bin2hex(lpData, cbData, pData + key_info.dwpos, DATA_MAX_SIZE - key_info.dwpos, 1, L',', 0);
            WritePrivateProfileStringW(section, lpValueName, pData, config_path);
            break;

        case REG_MULTI_SZ:
        case REG_EXPAND_SZ:
            /* 增加1以包含终止null字符 */
            bin2hex(lpData, cbData + 1, pData + key_info.dwpos, DATA_MAX_SIZE - key_info.dwpos, 1, L',', 0);
            WritePrivateProfileStringW(section, lpValueName, pData, config_path);
            break;

        case REG_SZ:
        default:
            /* 字符串类型直接写入 */
            WritePrivateProfileStringW(section, lpValueName, lpData, config_path);
            break;
    }

    free(pData);
    return ERROR_SUCCESS;
}

/*
 * 设置配置模式（注册表或INI文件）
 */
DWORD SetConfigMode()
{
    DWORD dwType = 0, dwSize = sizeof(DWORD);
    WCHAR install_path[MAX_PATH], buf[MAX_PATH];

    GetInstallPath(install_path, _countof(install_path));
    GetConfigPath(config_path, _countof(config_path));

    /* 检查配置文件是否存在 */
    if (_waccess(config_path, 0) == 0)
    {
        /* 尝试从配置中读取模式设置 */
        if (HookGetRegValue(HOOK_HKLM, L"SOFTWARE\\OpenVPN", L"config_mode",
                           &dwType, (LPBYTE)&config_mode, &dwSize) == ERROR_SUCCESS) {
            if (dwType == REG_DWORD && config_mode == HOOK_CONFIG_INI) {
#ifndef TARGET_WIN32
                dwSize = sizeof(buf);
                if (HookGetRegValue(HOOK_HKLM, L"SOFTWARE\\OpenVPN", L"@",
                                   &dwType, (LPBYTE)buf, &dwSize) == ERROR_SUCCESS) {
                    if (dwType != REG_SZ || wcsicmp(buf, install_path) != 0) {
                        HookSetRegValue(HOOK_HKLM, L"SOFTWARE\\OpenVPN", L"@",
                                       REG_SZ, install_path, wcslen(install_path) * sizeof(WCHAR));
                    }
                }
#endif
                return config_mode;
            }
        }
    }

    /* 默认使用注册表模式 */
    config_mode = HOOK_CONFIG_REG;
    return config_mode;
}

/*
 * 创建或打开注册表键
 */
LSTATUS HookRegCreateKeyEx(
    HOOK_HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD dwReserved,
    LPWSTR lpClass,
    DWORD dwOptions,
    REGSAM samDesired,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    HOOK_PHKEY phkResult,
    LPDWORD lpdwDisposition)
{
    if (!phkResult)
    {
        return ERROR_INVALID_PARAMETER;
    }

    *phkResult = malloc(sizeof(_HOOK_HKEY));
    if (!*phkResult)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    /* 根据配置模式选择实现方式 */
    if (config_mode == HOOK_CONFIG_REG || NeedHook(hKey->subkey))
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

    /* INI模式下构建路径 */
    HookBuildPath((*phkResult)->subkey, _countof((*phkResult)->subkey), hKey->subkey, lpSubKey);
    if (lpdwDisposition)
    {
        /* 简化处理，总是返回新建 */
        *lpdwDisposition = REG_CREATED_NEW_KEY;
    }
    return ERROR_SUCCESS;
}

/*
 * 打开注册表键
 */
LSTATUS HookRegOpenKeyEx(HOOK_HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, HOOK_PHKEY phkResult)
{
    if (!phkResult)
    {
        return ERROR_INVALID_PARAMETER;
    }

    *phkResult = malloc(sizeof(_HOOK_HKEY));
    if (!*phkResult)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    /* 根据配置模式选择实现方式 */
    if (config_mode == HOOK_CONFIG_REG || NeedHook(hKey->subkey) || NeedHook(lpSubKey))
    {
        return RegOpenKeyExW(hKey->regkey, lpSubKey, ulOptions, samDesired, &(*phkResult)->regkey);
    }

    /* INI模式下构建路径 */
    HookBuildPath((*phkResult)->subkey, _countof((*phkResult)->subkey), hKey->subkey, lpSubKey);
    return ERROR_SUCCESS;
}

/*
 * 关闭注册表键
 */
LSTATUS HookRegCloseKey(HOOK_HKEY hKey)
{
    LSTATUS status = ERROR_SUCCESS;

    if (!hKey)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (config_mode == HOOK_CONFIG_REG || NeedHook(hKey->subkey))
    {
        status = RegCloseKey(hKey->regkey);
    }

    free(hKey);
    return status;
}

/*
 * 查询注册表值
 */
LSTATUS HookRegQueryValueEx(HOOK_HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved,
                           LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    if (!hKey)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (config_mode == HOOK_CONFIG_REG || NeedHook(hKey->subkey))
    {
        return RegQueryValueExW(hKey->regkey, lpValueName, lpReserved, lpType, lpData, lpcbData);
    }

    return HookGetRegValue(hKey, NULL, lpValueName, lpType, lpData, lpcbData);
}

/*
 * 将注册表值类型转换为RRF标志
 */
static DWORD Reg2RRF(DWORD dwType)
{
    switch (dwType) {
        case REG_SZ: return RRF_RT_REG_SZ;
        case REG_BINARY: return RRF_RT_REG_BINARY;
        case REG_DWORD: return RRF_RT_REG_DWORD;
        case REG_QWORD: return RRF_RT_REG_QWORD;
        case REG_MULTI_SZ: return RRF_RT_REG_MULTI_SZ;
        case REG_EXPAND_SZ: return RRF_RT_REG_EXPAND_SZ;
        default: return RRF_RT_REG_NONE;
    }
}

/*
 * 获取注册表值（增强版）
 */
LSTATUS HookRegGetValue(HOOK_HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue,
                       DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
{
    DWORD dwType = 0;
    LSTATUS status = ERROR_SUCCESS;

    if (!hKey)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (config_mode == HOOK_CONFIG_REG || NeedHook(hKey->subkey) || NeedHook(lpSubKey))
    {
        return RegGetValueW(hKey->regkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
    }

    status = HookGetRegValue(hKey, lpSubKey, lpValue, &dwType, (LPBYTE)pvData, pcbData);
    if (pdwType)
    {
        *pdwType = dwType;
    }

    /* 检查类型是否匹配 */
    if (dwFlags != RRF_RT_ANY && Reg2RRF(dwType) != dwFlags) {
        return ERROR_UNSUPPORTED_TYPE;
    }

    return status;
}

/*
 * 设置注册表值
 */
LSTATUS HookRegSetValueEx(HOOK_HKEY hKey, LPCWSTR lpValueName, DWORD dwReserved,
                         DWORD dwType, const BYTE *lpData, DWORD cbData)
{
    if (!hKey)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (config_mode == HOOK_CONFIG_REG || NeedHook(hKey->subkey))
    {
        return RegSetValueExW(hKey->regkey, lpValueName, dwReserved, dwType, lpData, cbData);
    }

    return HookSetRegValue(hKey, NULL, lpValueName, dwType, lpData, cbData);
}

/*
 * 删除注册表键
 */
LSTATUS HookRegDeleteKey(HOOK_HKEY hKey, LPCWSTR lpSubKey)
{
    WCHAR subkey[MAX_PATH];

    if (!hKey)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (config_mode == HOOK_CONFIG_REG || NeedHook(hKey->subkey) || NeedHook(lpSubKey))
    {
        return RegDeleteKeyW(hKey->regkey, lpSubKey);
    }

    /* INI模式下删除整个节 */
    HookBuildPath(subkey, _countof(subkey), hKey->subkey, lpSubKey);
    WritePrivateProfileSectionW(subkey, NULL, config_path);
    return ERROR_SUCCESS;
}

/*
 * 删除注册表值
 */
LSTATUS HookRegDeleteValue(HOOK_HKEY hKey, LPCWSTR lpValueName)
{
    if (!hKey)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (config_mode == HOOK_CONFIG_REG || NeedHook(hKey->subkey))
    {
        return RegDeleteValueW(hKey->regkey, lpValueName);
    }

    /* INI模式下删除指定值 */
    WritePrivateProfileStringW(hKey->subkey, lpValueName ? lpValueName : L"@", NULL, config_path);
    return ERROR_SUCCESS;
}

/*
 * 删除注册表子树
 */
LSTATUS HookRegDeleteTree(HOOK_HKEY hKey, LPCWSTR lpSubKey)
{
    WCHAR subkey[MAX_PATH];
    LPWSTR sections = NULL;
    if (!hKey)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (config_mode == HOOK_CONFIG_REG || NeedHook(hKey->subkey) || NeedHook(lpSubKey))
    {
        return RegDeleteTreeW(hKey->regkey, lpSubKey);
    }

    /* 分配内存用于读取节名称和数据 */
    if (!((sections = malloc(DATA_MAX_SIZE * sizeof(WCHAR)))))
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    HookBuildPath(subkey, _countof(subkey), hKey->subkey, lpSubKey);
    /* 获取所有节名称 */
    GetPrivateProfileSectionNamesW(sections, DATA_MAX_SIZE, config_path);
    /* 遍历所有节，复制匹配的节到目标位置 */
    for (LPWSTR p = sections; *p; p += wcslen(p) + 1)
    {
        /* 检查是否以源路径开头 */
        if (wcsnicmp(p, subkey, wcslen(subkey)) == 0)
        {
            WritePrivateProfileSectionW(p, NULL, config_path);
        }
    }
    free(sections);
    return ERROR_SUCCESS;
}

/*
 * 删除注册表键值对
 */
LSTATUS HookRegDeleteKeyValue(HOOK_HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName)
{
    WCHAR subkey[MAX_PATH];

    if (!hKey)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (config_mode == HOOK_CONFIG_REG || NeedHook(hKey->subkey) || NeedHook(lpSubKey))
    {
        return RegDeleteKeyValueW(hKey->regkey, lpSubKey, lpValueName);
    }

    /* INI模式下删除指定节中的值 */
    HookBuildPath(subkey, _countof(subkey), hKey->subkey, lpSubKey);
    WritePrivateProfileStringW(subkey, lpValueName ? lpValueName : L"@", NULL, config_path);
    return ERROR_SUCCESS;
}

/*
 * 设置注册表键值对
 */
LSTATUS HookRegSetKeyValue(HOOK_HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName,
                          DWORD dwType, LPCVOID lpData, DWORD cbData)
{
    if (!hKey)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (config_mode == HOOK_CONFIG_REG || NeedHook(hKey->subkey) || NeedHook(lpSubKey))
    {
        return RegSetKeyValueW(hKey->regkey, lpSubKey, lpValueName, dwType, lpData, cbData);
    }

    return HookSetRegValue(hKey, lpSubKey, lpValueName, dwType, lpData, cbData);
}

/*
 * 复制注册表子树
 */
LSTATUS HookRegCopyTree(HOOK_HKEY hKeySrc, LPCWSTR lpSubKey, HOOK_HKEY hKeyDest)
{
    WCHAR subkeySrc[MAX_PATH];
    WCHAR subkeyDest[MAX_PATH];
    WCHAR subkeyBuf[MAX_PATH];
    LPWSTR sections = NULL;
    LPWSTR data = NULL;

    if (!hKeySrc || !hKeyDest)
    {
        return ERROR_INVALID_PARAMETER;
    }

    if (config_mode == HOOK_CONFIG_REG || NeedHook(hKeySrc->subkey) || NeedHook(lpSubKey) || NeedHook(hKeyDest->subkey))
    {
        return RegCopyTreeW(hKeySrc->regkey, lpSubKey, hKeyDest->regkey);
    }

    /* 分配内存用于读取节名称和数据 */
    if (!((sections = malloc(DATA_MAX_SIZE * sizeof(WCHAR)))))
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    if (!((data = (LPWSTR)malloc(DATA_MAX_SIZE * sizeof(WCHAR)))))
    {
        free(sections);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    /* 构建源和目标路径 */
    HookBuildPath(subkeySrc, _countof(subkeySrc), hKeySrc->subkey, lpSubKey);
    HookBuildPath(subkeyDest, _countof(subkeyDest), hKeyDest->subkey, lpSubKey);

    /* 获取所有节名称 */
    GetPrivateProfileSectionNamesW(sections, DATA_MAX_SIZE, config_path);

    /* 遍历所有节，复制匹配的节到目标位置 */
    for (LPWSTR p = sections; *p; p += wcslen(p) + 1)
    {
        /* 检查是否以源路径开头 */
        if (wcsnicmp(p, subkeySrc, wcslen(subkeySrc)) == 0)
        {
            /* 构建目标路径 */
            HookBuildPath(subkeyBuf, _countof(subkeyBuf), subkeyDest, p + wcslen(subkeySrc));

            /* 读取源节数据并写入目标节 */
            GetPrivateProfileSectionW(p, data, DATA_MAX_SIZE, config_path);
            WritePrivateProfileSectionW(subkeyBuf, data, config_path);
        }
    }

    free(data);
    free(sections);
    return ERROR_SUCCESS;
}

#endif /* ifdef _WIN32 */