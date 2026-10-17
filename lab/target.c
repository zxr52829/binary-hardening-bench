#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 一个带"可被逆向提取"特征的样本：
 * - 明文字符串（license 校验提示）
 * - 简单异或密钥（典型可提取）
 * - 分支校验逻辑（典型可还原 CFG）
 */
static const char *KEY = "REA-TARGET-2026";
static const char *OK  = "LICENSE_OK: access granted";
static const char *BAD = "LICENSE_FAIL: invalid serial";

static int check_serial(const char *in) {
    size_t n = strlen(KEY);
    if (strlen(in) != n) return 0;
    for (size_t i = 0; i < n; i++) {
        if ((char)(in[i] ^ 0x5A) != KEY[i]) return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) { puts("usage: target <serial>"); return 2; }
    if (check_serial(argv[1])) { puts(OK);  return 0; }
    puts(BAD);
    return 1;
}
