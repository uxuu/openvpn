#ifndef HOOK_REGHOOK_H
#define HOOK_REGHOOK_H

#ifdef _WIN32

extern DWORD config_mode;

typedef struct {
    HKEY regkey;
    WCHAR subkey[MAX_PATH];
    DWORD dwFlags;
} _HOOK_HKEY, *HOOK_HKEY, **HOOK_PHKEY;

extern const HOOK_HKEY HOOK_HKCR;
extern const HOOK_HKEY HOOK_HKLM;
extern const HOOK_HKEY HOOK_HKCU;


#define HookRegOpenKeyEx HookRegOpenKeyExW
#define HookRegCreateKeyEx HookRegCreateKeyExW
#define HookRegQueryValueEx HookRegQueryValueExW
#define HookRegGetValue HookRegGetValueW
#define HookRegSetValueEx HookRegSetValueExW
#define HookRegDeleteKey HookRegDeleteKeyW
#define HookRegDeleteValue HookRegDeleteValueW
#define HookRegDeleteTree HookRegDeleteTreeW
#define HookRegDeleteKeyValue HookRegDeleteKeyValueW
#define HookRegSetKeyValue HookRegSetKeyValueW
#define HookRegCopyTree HookRegCopyTreeW


DWORD SetConfigMode();
DWORD GetInstallPath(LPWSTR lpPath, DWORD dwSize);
LSTATUS HookRegOpenKeyEx(HOOK_HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, HOOK_PHKEY phkResult);
LSTATUS HookRegCreateKeyEx(HOOK_HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions,
    REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, HOOK_PHKEY phkResult, LPDWORD lpdwDisposition);
LSTATUS HookRegQueryValueEx(HOOK_HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
LSTATUS HookRegGetValue(HOOK_HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);
LSTATUS HookRegSetValueEx(HOOK_HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
LSTATUS HookRegDeleteKey(HOOK_HKEY hKey, LPCWSTR lpSubKey);
LSTATUS HookRegDeleteValue(HOOK_HKEY hKey, LPCWSTR lpValueName);
LSTATUS HookRegDeleteTree(HOOK_HKEY hKey, LPCWSTR lpSubKey);
LSTATUS HookRegDeleteKeyValue(HOOK_HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName);
LSTATUS HookRegSetKeyValue(HOOK_HKEY hKey, LPCWSTR lpSubKey, LPCWSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData);
LSTATUS HookRegCopyTree(HOOK_HKEY hKeySrc, LPCWSTR lpSubKey, HOOK_HKEY hKeyDest);
LSTATUS HookRegCloseKey(HOOK_HKEY hKey);

#ifndef HOOK_REG_NOHOOK

#define HKEY HOOK_HKEY
#define PHKEY HOOK_PHKEY

#undef HKEY_CLASSES_ROOT
#undef HKEY_LOCAL_MACHINE
#undef HKEY_CURRENT_USER
#define HKEY_CLASSES_ROOT HOOK_HKCR
#define HKEY_LOCAL_MACHINE HOOK_HKLM
#define HKEY_CURRENT_USER HOOK_HKCU

#define RegOpenKeyExW HookRegOpenKeyExW
#define RegCreateKeyExW HookRegCreateKeyExW
#define RegQueryValueExW HookRegQueryValueExW
#define RegGetValueW HookRegGetValueW
#define RegSetValueExW HookRegSetValueExW
#define RegDeleteKeyW HookRegDeleteKeyW
#define RegDeleteValueW HookRegDeleteValueW
#define RegDeleteTreeW HookRegDeleteTreeW
#define RegDeleteKeyValueW HookRegDeleteKeyValueW
#define RegSetKeyValueW HookRegSetKeyValueW
#define RegCopyTreeW HookRegCopyTreeW

#define RegCloseKey HookRegCloseKey

#endif /* ifndef HOOK_REG_NOHOOK */


#endif /* ifdef _WIN32 */

#endif  // HOOK_REGHOOK_H
