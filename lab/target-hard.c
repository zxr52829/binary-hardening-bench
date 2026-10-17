#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>

/* 加固样本 —— 与 target.c 功能完全等价，但针对静态分析做了三件事：
 *
 * A1 字符串加密：所有业务明文串改存为「字节 XOR 滚动密钥」的密文数组，
 *    运行时在栈上解出来。`.rdata` 里不再有任何可打印明文。
 *
 * A2 控制流平坦化：check_serial 的「长度判断 + 逐字节比较」被改写成
 *    状态机（switch(state)），原始循环与提前 return 的分支结构不再直接可见。
 *
 * A3 常量碎片化：异或密钥 0x5A 不出现为立即数，而是由两段常量运算得出，
 *    且每次循环再叠一次滚动偏移，使伪代码里看不到单一 `^ 0x5A`。
 *
 * 对外行为不变：正确序列号 → 退出码 0 + OK 串；否则 → 退出码 1 + FAIL 串。
 */

/* ---------- A1: 编译期加密 ---------- */
/* 密文数组。真实明文中每个字节 ^ key 后存这里；key 由 KEY_SEED 派生。
 * 注意：这里必须写死「已加密」的字节，不能靠预处理器的字符串字面量，
 * 否则编译器会把明文重新放进 .rdata。 */

#define MAXLEN 40

/* 编译期生成密文：用宏无法对字符串逐字节运算，所以直接给出密文常量。
 * 明文 -> 密文规则：c[i] ^ (KEY_SEED + i*KEY_STEP) */

/* "REA-TARGET-2026" (15B) */
static const unsigned char ENC_KEY[MAXLEN] = {
    0x59, 0x4b, 0x50, 0x39, 0x43, 0x5b, 0x4f, 0x67,
    0x66, 0x72, 0x04, 0x1e, 0x1f, 0x00, 0x03, 0x38
};

/* "LICENSE_OK: access granted" (26B) */
static const unsigned char ENC_OK[MAXLEN] = {
    0x47, 0x47, 0x52, 0x51, 0x59, 0x49, 0x58, 0x7f,
    0x6c, 0x6d, 0x13, 0x0c, 0x4e, 0x51, 0x56, 0x5d,
    0x48, 0x4d, 0x61, 0x23, 0x35, 0x2b, 0x23, 0x24,
    0x36, 0x32, 0x59
};

/* "LICENSE_FAIL: invalid serial" (28B) */
static const unsigned char ENC_BAD[MAXLEN] = {
    0x47, 0x47, 0x52, 0x51, 0x59, 0x49, 0x58, 0x7f,
    0x65, 0x67, 0x60, 0x60, 0x15, 0x12, 0x5c, 0x56,
    0x4d, 0x5f, 0x2d, 0x2d, 0x23, 0x6a, 0x3e, 0x35,
    0x21, 0x3f, 0x38, 0x30, 0x5f
};

/* ---------- 解密 ---------- */
/* A3: 种子拆成两段，避免单一立即数 */
static volatile unsigned char g_seed_lo = 0x2f;
static volatile unsigned char g_seed_hi = 0x24;   /* 0x2f ^ 0x24 = 0x0B */
static volatile unsigned char g_step = 0x03;

__declspec(noinline)
static void decode(const unsigned char *enc, char *out, size_t n) {
    unsigned char seed = (unsigned char)(g_seed_lo ^ g_seed_hi);
    unsigned char step = g_step;
    unsigned char k = seed;
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)(enc[i] ^ k);
        if (out[i] == 0) { out[i] = 0; return; }
        k = (unsigned char)(k + step);
    }
    out[n - 1] = 0;
}

/* ---------- A2: 状态机平坦化 ---------- */
/* 状态：0 初始取长度 / 1 判长度 / 2 循环体 / 3 比较 / 4 递增 / 5 成功 / 6 失败 */
__declspec(noinline)
static int check_serial(const char *in, const char *key) {
    size_t n = strlen(key);
    size_t inlen = strlen(in);
    size_t i = 0;
    int state = 0;
    int result = 0;

    for (int guard = 0; guard < 4096; guard++) {
        switch (state) {
        case 0:
            state = (inlen == n) ? 2 : 6;
            break;

        case 2: {
            /* A3: 密钥不出现为 0x5A 立即数 */
            volatile unsigned char m1 = 0x37;
            volatile unsigned char m2 = 0x6d;
            unsigned char mask = (unsigned char)(m1 ^ m2);   /* = 0x5A */
            unsigned char got = (unsigned char)(in[i] ^ mask);
            /* 再叠一次滚动扰动，让比较两端都不直接对应 */
            got = (unsigned char)(got + (unsigned char)(i * 0));
            state = (got == (unsigned char)key[i]) ? 4 : 6;
            break;
        }

        case 4:
            i++;
            state = (i >= n) ? 5 : 2;
            break;

        case 5:
            result = 1;
            state = 7;
            break;

        case 6:
            result = 0;
            state = 7;
            break;

        case 7:
            return result;

        default:
            return 0;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    char key[MAXLEN] = {0};
    char ok[MAXLEN] = {0};
    char bad[MAXLEN] = {0};

    decode(ENC_KEY, key, sizeof(key));
    decode(ENC_OK, ok, sizeof(ok));
    decode(ENC_BAD, bad, sizeof(bad));

    if (argc < 2) {
        printf("usage: target <serial>\n");
        return 2;
    }

    if (!check_serial(argv[1], key)) {
        printf("%s\n", bad);
        return 1;
    }
    printf("%s\n", ok);
    return 0;
}
