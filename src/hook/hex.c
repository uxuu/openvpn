#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <windows.h>
#include "hex.h"

/*
 * 将二进制数据转换为十六进制字符串
 * @param data 输入的二进制数据
 * @param datalen 输入数据长度
 * @param buf 输出缓冲区
 * @param buflen 输出缓冲区大小
 * @param group_size 分组大小（1、2或4字节）
 * @param separator 分隔符字符串（如空格、冒号等）
 * @param bytes_per_line 每行字节数，0表示不换行
 * @return 生成的十六进制字符串长度（不包括终止符）
 */
int bin2hex(const BYTE *data, const int datalen, LPWSTR buf, int buflen,
               int group_size, const WCHAR sp, int line_bytes)
{
    const WCHAR hex_dict[] = L"0123456789ABCDEF";
    int i, j;

    /* 参数检查 */
    if (!data || !buf || buflen <= 0 || datalen <= 0)
        return 0;

    /* 检查分组大小 */
    if (group_size < 0)
        group_size = 0;  /* 默认为1字节分组 */

    /* 检查每行字节数 */
    if (line_bytes < 0)
        line_bytes = 0; /* 负数视为不换行 */

    /* 转换数据为十六进制字符串 */
    for (i = 0, j = 0; i < datalen && j < buflen - 1; i++)
    {
        /* 转换当前字节 */
        buf[j++] = hex_dict[(data[i] >> 4) & 0x0F];
        buf[j++] = hex_dict[data[i] & 0x0F];

        /* 检查是否需要添加分隔符 */
        if ((i + 1) % group_size == 0 && j + 1 < buflen )
        {
            buf[j++] = sp;
        }

        /* 检查是否需要添加换行符 */
        if (line_bytes > 0 && (i + 1) % line_bytes == 0 && j + 2 < buflen)
        {
            /* 添加换行符 */
            buf[j++] = L'\r';
            buf[j++] = L'\n';
        }
    }

    return j;
}

/*
 * 将十六进制字符串转换为二进制数据
 * @param data 输入的十六进制字符串
 * @param datalen 输入字符串长度
 * @param buf 输出缓冲区
 * @param buflen 输出缓冲区大小
 * @return 转换后的二进制数据长度
 */
int hex2bin(const LPWSTR data, const int datalen, BYTE *buf, int buflen)
{
    const WCHAR hex_chars[] = L"0123456789ABCDEFabcdef";
    int i, j;
    BYTE val = 0;
    LPWSTR p;
    int high_nibble = 1;  /* 1表示处理高4位，0表示处理低4位 */

    if (!data || !buf || buflen <= 0)
        return 0;

    for (i = 0, j = 0; i < datalen && j < buflen; i++)
    {
        /* 跳过空格和逗号和换行 */
        if (buf[i] == L' ' || buf[i] == L',' || buf[i] == L'\r' || buf[i] == L'\n')
            continue;

        /* 检查是否为十六进制字符 */
        if (!((p = wcschr(hex_chars, buf[i]))))
            continue;

        /* 转换字符为数值 */
        val = (BYTE)(p - hex_chars);
        if (val > 0x0F)
            val -= 6;  /* 调整a-f的值 */

        if (high_nibble)
        {
            /* 存储高4位 */
            data[j] = val << 4;
        }
        else
        {
            /* 组合低4位，完成一个字节 */
            data[j] |= val;
            j++;
        }

        high_nibble = !high_nibble;
    }

    /* 如果以高4位结束，说明输入数据不完整, 忽略不完整字节 */
    if(!high_nibble)
        data[j--] = 0;

    return j;
}