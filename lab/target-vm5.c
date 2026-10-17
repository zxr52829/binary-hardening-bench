#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ============================================================================
 * 加固样本 A5 —— 操作码混淆 + 字节码加密
 *
 * 在 A4（控制流虚拟化）之上再加两层：
 *
 *   L1 字节码加密
 *       磁盘上的 PROGRAM 是密文。解释器启动时用「种子流」解到栈上。
 *       逆向者在文件里看到的是一段无意义字节，看不出指令边界。
 *
 *   L2 操作码置换（运行期生成）
 *       源码里的真实操作码（0x11/0x22/...）从不出现在字节码里。
 *       运行期用一个种子生成 256 字节置换表 perm[]，
 *       字节码里存的是 shuffled = perm[real_op]。
 *       解释器执行时 real_op = inv[shuffled]。
 *
 *       关键：perm/inv 由运行时算出的种子派生，静态读文件拿不到。
 *       即使对手完整读懂了解释器的 switch 分支语义，
 *       他仍然需要重新跑一遍密钥派生才能把字节码翻译回真实操作码。
 *
 * 业务语义与 target.c 完全一致：
 *     if (strlen(in) != strlen(KEY)) return 0;
 *     for (i = 0; i < n; i++)
 *         if ((in[i] ^ 0x5A) != KEY[i]) return 0;
 *     return 1;
 * ==========================================================================*/

#define MAXLEN 64

/* ---------- VM 真实指令集（不会出现在二进制数据段） ---------- */
enum {
    OP_HALT    = 0x00,
    OP_LOADK   = 0x11,
    OP_DECRYPT = 0x22,
    OP_STRLEN  = 0x33,
    OP_CMP     = 0x44,
    OP_JZ      = 0x55,
    OP_MOV     = 0x66,
    OP_GETBYTE = 0x77,
    OP_GETKEY  = 0x88,
    OP_XORI    = 0x99,
    OP_INC     = 0xAA,
    OP_JMP     = 0xBB,
    OP_RET     = 0xCC,
    OP_LOADI   = 0xDD,
    OP_EQ      = 0xEE,
    OP_JNZ     = 0xFF
};

/* ---------- A1 字符串密文（与 target-hard 相同方案） ---------- */
static const unsigned char ENC_KEY[] = {
    0x59,0x4b,0x50,0x39,0x43,0x5b,0x4f,0x67,0x66,0x72,0x04,0x1e,0x1f,0x00,0x03,0x38
};
static const unsigned char ENC_OK[] = {
    0x47,0x47,0x52,0x51,0x59,0x49,0x58,0x7f,0x6c,0x6d,0x13,0x0c,0x4e,0x51,
    0x56,0x5d,0x48,0x4d,0x61,0x23,0x35,0x2b,0x23,0x24,0x36,0x32,0x59
};
static const unsigned char ENC_BAD[] = {
    0x47,0x47,0x52,0x51,0x59,0x49,0x58,0x7f,0x65,0x67,0x60,0x60,0x15,0x12,0x5c,
    0x56,0x4d,0x5f,0x2d,0x2d,0x23,0x6a,0x3e,0x35,0x21,0x3f,0x38,0x30,0x5f
};

/* ---------- 明文程序（只在构建期用于生成密文，不进二进制） ----------
 *
 *   pc    指令
 *   0x00  DECRYPT 0x00        ; key
 *   0x02  DECRYPT 0x01        ; ok
 *   0x04  DECRYPT 0x02        ; bad
 *   0x06  STRLEN 0x01         ; len(key)
 *   0x08  STRLEN 0x02         ; len(in)
 *   0x0a  EQ                  ; 相等?
 *   0x0b  JZ 0x23             ; 不等 -> bad
 *   0x0d  MOV                 ; i = 0
 *   0x0e  LOADI               ; ^ i
 *   0x0f  STRLEN 0x01         ; ^ len(key)
 *   0x11  CMP                 ; i < len ?
 *   0x12  JZ 0x20             ; 否 -> ok
 *   0x14  GETBYTE             ; in[i]
 *   0x15  XORI 0x37
 *   0x17  XORI 0x6d           ; 合计 ^0x5A（A3 碎片化）
 *   0x19  GETKEY              ; key[i]
 *   0x1a  EQ
 *   0x1b  JZ 0x23             ; 不等 -> bad
 *   0x1d  INC                 ; i++
 *   0x1e  JMP 0x0e            ; 回 loop
 *   0x20  LOADK 0x01 / RET    ; -> 1
 *   0x23  LOADK 0x00 / RET    ; -> 0
 *   0x26  HALT
 * ------------------------------------------------------------------ */

/* ---------- 运行期派生：种子 → 置换表 + 解密流 ---------- */

/*
 * 种子派生。刻意不使用明显的常量拼接：
 * 这里喂进去的是两段看似无关的数组长度差与字符偏移，
 * 静态阅读时不像"密钥"，但运行期结果确定。
 *
 * ⚠ 注意：不能用「数组地址差」——那是链接期决定的，构建脚本无法预先算出一致值。
 * 只用编译期常量（长度、元素值）保证 JS 侧可以同步复现。
 */
__declspec(noinline)
static unsigned int derive_seed(void) {
    unsigned int s = 0x9e3779b9u;
    s ^= (unsigned int)(sizeof(ENC_KEY) * 0x01000193u);   /* 16 * 16777619 */
    s += (unsigned int)(sizeof(ENC_BAD) << 7);            /* 29 << 7 */
    s ^= (unsigned int)(ENC_OK[0] << 16);
    s ^= (unsigned int)(ENC_KEY[1] << 8);
    s ^= 0x5bf03635u;
    /* 再来几轮雪崩，把上面的线性关系彻底打散 */
    for (int r = 0; r < 4; r++) {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
    }
    return s ? s : 1;
}

/*
 * 生成 256 字节置换表。
 * table[i] = i 的混淆像。用线性同余 + 位混淆，保证是双射（可逆）。
 * 逆表在需要时由调用方另存。
 */
__declspec(noinline)
static void build_perm(unsigned char *tab, unsigned int seed) {
    /* 先做一次 Fisher-Yates 式的确定性置换：以 seed 为伪随机源 */
    unsigned char idx[256];
    for (int i = 0; i < 256; i++) idx[i] = (unsigned char)i;

    unsigned int x = seed;
    for (int i = 255; i > 0; i--) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        int j = (int)(x % (unsigned int)(i + 1));
        unsigned char t = idx[i]; idx[i] = idx[j]; idx[j] = t;
    }
    /* tab[real] = shuffled */
    memcpy(tab, idx, 256);
}

/* ---------- 运行时状态 ---------- */
typedef struct {
    char  buf[3][MAXLEN];   /* 0=key 1=ok 2=bad */
    char  input[MAXLEN];
    int   i;
    int   stack[16];
    int   sp;
    unsigned char inv[256]; /* 逆置换：shuffled -> real */
} VM;

static void push(VM *vm, int v) { if (vm->sp < 16) vm->stack[vm->sp++] = v; }
static int  pop(VM *vm)        { return vm->sp > 0 ? vm->stack[--vm->sp] : 0; }

/* A1 滚动密钥解密，种子/步长同样碎片化 */
__declspec(noinline)
static void vm_decrypt(const unsigned char *enc, char *out, int max) {
    unsigned char a = 0x2f, b = 0x24, s = 0x03;
    unsigned char seed = (unsigned char)(a ^ b);
    unsigned char k = seed;
    for (int j = 0; j < max; j++) {
        char c = (char)(enc[j] ^ k);
        out[j] = c;
        if (c == 0) return;
        k = (unsigned char)(k + s);
    }
    out[max - 1] = 0;
}

/* ---------- 字节码解密器 ----------
 * 密文布局：[0] = 长度，[1..] = 密文
 * 解密流由 seed 派生，与置换表共用一个种子但走不同的混淆。
 */
__declspec(noinline)
static int unpack_program(const unsigned char *enc, unsigned char *out, int cap, unsigned int seed) {
    int n = enc[0];
    if (n <= 0 || n > cap) return 0;
    unsigned int x = seed ^ 0xa5a5a5a5u;
    for (int i = 0; i < n; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        out[i] = (unsigned char)(enc[1 + i] ^ (unsigned char)(x >> 3));
    }
    return n;
}

/* ---------- 解释器 ----------
 * 关键：字节码里的操作码是「置换后的像」，
 * 执行前先经 vm->inv[] 还原成真实操作码。
 * 对手在 switch 里看到的是真实操作码常量，
 * 但拿到的数据是混淆像——必须自己跑 derive_seed + build_perm 才能对上。
 */
__declspec(noinline)
static int vm_run(const unsigned char *prog, int proglen, VM *vm) {
    int pc = 0;
    int guard = 0;

    while (pc >= 0 && pc < proglen && guard++ < 100000) {
        unsigned char raw = prog[pc++];
        unsigned char op = vm->inv[raw];   /* ← 关键还原步骤 */

        switch (op) {
        case OP_DECRYPT: {
            int id = prog[pc++];
            const unsigned char *src = (id == 0) ? ENC_KEY : (id == 1) ? ENC_OK : ENC_BAD;
            vm_decrypt(src, vm->buf[id], MAXLEN);
            break;
        }

        case OP_STRLEN: {
            int which = prog[pc++];
            const char *s = (which == 1) ? vm->buf[0] : vm->input;
            push(vm, (int)strlen(s));
            break;
        }

        case OP_LOADK: {
            push(vm, prog[pc++]);
            break;
        }

        case OP_CMP: {
            int b2 = pop(vm);
            int a2 = pop(vm);
            push(vm, (a2 < b2) ? 1 : 0);
            break;
        }

        case OP_EQ: {
            int b2 = pop(vm);
            int a2 = pop(vm);
            push(vm, (a2 == b2) ? 1 : 0);
            break;
        }

        case OP_JZ: {
            int t = prog[pc++];
            int cond = pop(vm);
            if (cond == 0) pc = t;
            break;
        }

        case OP_JNZ: {
            int t = prog[pc++];
            int cond = pop(vm);
            if (cond != 0) pc = t;
            break;
        }

        case OP_JMP: {
            pc = prog[pc];
            break;
        }

        case OP_MOV: {
            vm->i = 0;
            push(vm, 0);
            break;
        }

        case OP_LOADI: {
            push(vm, vm->i);
            break;
        }

        case OP_GETBYTE: {
            push(vm, (unsigned char)vm->input[vm->i]);
            break;
        }

        case OP_GETKEY: {
            push(vm, (unsigned char)vm->buf[0][vm->i]);
            break;
        }

        case OP_XORI: {
            unsigned char imm = prog[pc++];
            int v = pop(vm);
            push(vm, v ^ imm);
            break;
        }

        case OP_INC: {
            vm->i++;
            break;
        }

        case OP_RET: {
            return pop(vm);
            }

        case OP_HALT:
        default:
            return 0;
        }
    }
    return 0;
}

/* ---------- 密文字节码（构建期由 gen-vm5.mjs 生成） ----------
 *
 * 拆成 4 段碎片分别定义。目的不是加密强度，而是避免「39 字节密文
 * 在文件里连续出现」——连续出现意味着对手可以一次性 byte-scan 抓走整段字节码。
 * 碎片化后必须理解 unpack_program 的拼接顺序才能重组。
 */
static const unsigned char SEG_A[] = { 0x27, 0x66, 0x92, 0x50, 0x34, 0x47, 0xbb, 0x14, 0x72, 0x1b };
static const unsigned char SEG_B[] = { 0x10, 0x59, 0x8a, 0xc5, 0x2f, 0x68, 0x10, 0xe3, 0x66, 0xe9 };
static const unsigned char SEG_C[] = { 0x35, 0xf5, 0x1d, 0xa1, 0x93, 0x4b, 0xb5, 0x59, 0x62, 0x02 };
static const unsigned char SEG_D[] = { 0x5c, 0xa1, 0x98, 0x7d, 0xdb, 0xcf, 0xde, 0xa8, 0x7e, 0x54 };

/*
 * 按 SEG_A..D 的顺序取回第 idx 个字节（跳过 [0] 长度字节的约定不变）。
 * 用取模索引而不是 memcpy 拼接，让编译器无法把这四段合并回一个连续数组。
 */
__declspec(noinline)
static unsigned char seg_byte(const unsigned char *segs[4], const int lens[4], int idx) {
    for (int s = 0; s < 4; s++) {
        if (idx < lens[s]) return segs[s][idx];
        idx -= lens[s];
    }
    return 0;
}

/* ---------- 入口 ---------- */
__declspec(noinline)
static int check_serial(const char *in, char *out_ok, char *out_bad) {
    VM vm;
    unsigned char prog[128];

    memset(&vm, 0, sizeof(vm));

    unsigned int seed = derive_seed();

    /* 重建逆置换表 inv[shuffled] = real */
    unsigned char perm[256];
    build_perm(perm, seed);
    for (int r = 0; r < 256; r++) {
        vm.inv[perm[r]] = (unsigned char)r;
    }

    /* 从碎片重建密文：[0] 是长度 */
    const unsigned char *segs[4] = { SEG_A, SEG_B, SEG_C, SEG_D };
    int lens[4] = { (int)sizeof(SEG_A), (int)sizeof(SEG_B), (int)sizeof(SEG_C), (int)sizeof(SEG_D) };
    int total = lens[0] + lens[1] + lens[2] + lens[3];

    unsigned char enc[128];
    for (int k = 0; k < total && k < (int)sizeof(enc); k++) enc[k] = seg_byte(segs, lens, k);

    int n = unpack_program(enc, prog, (int)sizeof(prog), seed);
    if (n <= 0) return 0;

    strncpy(vm.input, in, MAXLEN - 1);
    vm.input[MAXLEN - 1] = 0;

    int r = vm_run(prog, n, &vm);

    /* 把解释器解密出来的业务串交回调用方 —— 二进制里不存这些字面量 */
    strncpy(out_ok, vm.buf[1], MAXLEN - 1);
    out_ok[MAXLEN - 1] = 0;
    strncpy(out_bad, vm.buf[2], MAXLEN - 1);
    out_bad[MAXLEN - 1] = 0;

    return r;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: target <serial>\n");
        return 2;
    }

    char ok[MAXLEN];
    char bad[MAXLEN];
    int r = check_serial(argv[1], ok, bad);

    /* 两条消息都是运行期从 VM 缓冲区取出的，main 里没有任何业务字面量 */
    printf("%s\n", r ? ok : bad);
    return r ? 0 : 1;
}
