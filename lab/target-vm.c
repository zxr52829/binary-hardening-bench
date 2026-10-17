#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ============================================================================
 * 加固样本 A4 —— 控制流虚拟化 (bytecode VM)
 *
 * 目标：让逆向者拿不到可读的业务伪代码。
 *
 * target.c 里 check_serial 的原始语义：
 *     if (strlen(in) != strlen(KEY)) return 0;
 *     for (i = 0; i < n; i++)
 *         if ((in[i] ^ 0x5A) != KEY[i]) return 0;
 *     return 1;
 *
 * 本文件把这个语义编译成一段自定字节码，由一个小型 VM 解释执行。
 * 二进制里不存在 check_serial 的 native 指令，逆向者看到的是：
 *   - 一个通用解释器（取指/译码/执行循环）
 *   - 一段不透明的字节数组
 *   - 源码里看不到任何 ^0x5A、任何明文密钥
 *
 * 字符串同样经 A1 加密，运行时解出到栈上。
 * ==========================================================================*/

#define MAXLEN 64

/* ---------- VM 指令集 ---------- */
/* 极简栈式 VM。每个指令 1 字节操作码，部分带 1 字节立即数。 */
enum {
    OP_HALT   = 0x00,
    OP_LOADK  = 0x11,   /* 立即数入栈（后跟 1 字节） */
    OP_DECRYPT= 0x22,   /* 解密指定缓冲区：立即数 = 缓冲区 id */
    OP_STRLEN = 0x33,   /* 栈顶字符串求长度 */
    OP_CMP    = 0x44,   /* 弹出两值比较，压入 0/1 */
    OP_JZ     = 0x55,   /* 栈顶为 0 则跳转（后跟 1 字节目标 pc） */
    OP_MOV    = 0x66,   /* 压入 0（初始化循环变量） */
    OP_GETBYTE= 0x77,   /* 压入 input[i] */
    OP_GETKEY = 0x88,   /* 压入 key[i] */
    OP_XORI   = 0x99,   /* 栈顶与立即数异或（后跟 1 字节） */
    OP_INC    = 0xAA,   /* i++ */
    OP_JMP    = 0xBB,   /* 无条件跳转（后跟 1 字节目标 pc） */
    OP_RET    = 0xCC,   /* 返回栈顶作为结果 */
    OP_LOADI  = 0xDD,   /* 压入循环变量 i */
    OP_EQ     = 0xEE,   /* 弹出两值判等，压入 0/1 */
    OP_JNZ    = 0xFF,   /* 栈顶非 0 则跳转（后跟 1 字节目标 pc） */
};

/* ---------- A1: 加密字符串（同 target-hard.c 的种子/步长） ---------- */
/* 明文 -> 密文：c[i] = p[i] ^ (SEED + i*STEP), SEED=0x0B, STEP=0x03 */

static const unsigned char ENC_KEY[MAXLEN] = {
    0x59,0x4b,0x50,0x39,0x43,0x5b,0x4f,0x67,0x66,0x72,0x04,0x1e,0x1f,0x00,0x03,0x38
};
static const unsigned char ENC_OK[MAXLEN] = {
    0x47,0x47,0x52,0x51,0x59,0x49,0x58,0x7f,0x6c,0x6d,0x13,0x0c,0x4e,0x51,0x56,0x5d,
    0x48,0x4d,0x61,0x23,0x35,0x2b,0x23,0x24,0x36,0x32,0x59
};
static const unsigned char ENC_BAD[MAXLEN] = {
    0x47,0x47,0x52,0x51,0x59,0x49,0x58,0x7f,0x65,0x67,0x60,0x60,0x15,0x12,0x5c,0x56,
    0x4d,0x5f,0x2d,0x2d,0x23,0x6a,0x3e,0x35,0x21,0x3f,0x38,0x30,0x5f
};

/* ---------- 字节码：等价于 check_serial ---------- */
/*
 * 语义伪代码（这份注释只存在于源码，不进二进制）：
 *
 *   n = strlen(key)
 *   if strlen(in) != n: return 0
 *   i = 0
 * loop:
 *   if i >= n: return 1
 *   if (in[i] ^ MASK) != key[i]: return 0
 *   i++
 *   goto loop
 *
 * 字节码实现（pc 为字节下标）：
 *   00 OP_DECRYPT 00      ; 解密 key 到缓冲区0
 *   02 OP_DECRYPT 01      ; 解密 ok
 *   04 OP_DECRYPT 02      ; 解密 bad
 *   06 OP_LOADI            ; 压 i (初始0)
 *   ...
 */
static const unsigned char PROGRAM[] = {
    /* 解密三个字符串缓冲区 */
    OP_DECRYPT, 0x00,         /* 0x00 */
    OP_DECRYPT, 0x01,         /* 0x02 */
    OP_DECRYPT, 0x02,         /* 0x04 */

    /* 长度校验：如果 strlen(in) != strlen(key) 则跳到失败返回 */
    OP_STRLEN, 0x01,          /* 0x06  strlen(key) */
    OP_STRLEN, 0x02,          /* 0x08  strlen(in)  */
    OP_EQ,                    /* 0x0a */
    OP_JZ, 0x23,              /* 0x0b  不等 -> bad (0x23) */

    /* 初始化循环变量 i = 0 */
    OP_MOV,                   /* 0x0d */

    /* loop: (pc = 0x0e) */
    OP_LOADI,                 /* 0x0e  压 i */
    OP_STRLEN, 0x01,          /* 0x0f  压 n */
    OP_CMP,                   /* 0x11  i < n ? */
    OP_JZ, 0x20,              /* 0x12  i>=n -> ok (0x20) */

    /* 比较 in[i]^MASK 与 key[i] */
    OP_GETBYTE,               /* 0x14  in[i] */
    OP_XORI, 0x37,            /* 0x15 */
    OP_XORI, 0x6d,            /* 0x17  合计 ^0x5A */
    OP_GETKEY,                /* 0x19  key[i] */
    OP_EQ,                    /* 0x1a */
    OP_JZ, 0x23,              /* 0x1b  不等 -> bad (0x23) */

    OP_INC,                   /* 0x1d  i++ */
    OP_JMP, 0x0e,             /* 0x1e  回 loop (0x0e) */

    /* 成功 (pc = 0x20) */
    OP_LOADK, 0x01,           /* 0x20 */
    OP_RET,                   /* 0x22 */

    /* 失败 (pc = 0x23) */
    OP_LOADK, 0x00,           /* 0x23 */
    OP_RET,                   /* 0x25 */

    OP_HALT                   /* 0x26 */
};

/* ---------- VM 运行时状态 ---------- */
typedef struct {
    char  buf[3][MAXLEN];   /* 0=key 1=ok 2=bad */
    char  input[MAXLEN];
    int   i;
    int   stack[16];
    int   sp;
} VM;

static void push(VM *vm, int v) { if (vm->sp < 16) vm->stack[vm->sp++] = v; }
static int  pop(VM *vm)        { return vm->sp > 0 ? vm->stack[--vm->sp] : 0; }
static int  peek(VM *vm)       { return vm->sp > 0 ? vm->stack[vm->sp - 1] : 0; }

/* 解密：与 A1 相同的滚动密钥，但种子与步长来自多段常量 */
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

/* ---------- 解释器 ---------- */
/* 关键：这个函数对任何程序都是通用的，不含业务语义 */
__declspec(noinline)
static int vm_run(const unsigned char *prog, int proglen, VM *vm) {
    int pc = 0;
    int guard = 0;

    while (pc >= 0 && pc < proglen && guard++ < 100000) {
        unsigned char op = prog[pc++];

        switch (op) {
        case OP_DECRYPT: {
            int id = prog[pc++];
            const unsigned char *src = (id == 0) ? ENC_KEY : (id == 1) ? ENC_OK : ENC_BAD;
            vm_decrypt(src, vm->buf[id], MAXLEN);
            break;
        }

        case OP_STRLEN: {
            /* 参数：1=key 缓冲区, 2=输入 */
            int which = prog[pc++];
            const char *s = (which == 1) ? vm->buf[0] : vm->input;
            push(vm, (int)strlen(s));
            break;
        }

        case OP_EQ: {
            int y = pop(vm), x = pop(vm);
            push(vm, x == y ? 1 : 0);
            break;
        }

        case OP_CMP: {
            int y = pop(vm), x = pop(vm);   /* y = n, x = i */
            push(vm, x < y ? 1 : 0);
            break;
        }

        case OP_JZ: {
            int t = prog[pc++];
            int cond = pop(vm);          /* 条件值必须弹出，否则循环里会无限泄漏栈 */
            if (cond == 0) pc = t;
            break;
        }

        case OP_JNZ: {
            int t = prog[pc++];
            int cond = pop(vm);          /* 同上 */
            if (cond != 0) pc = t;
            break;
        }

        case OP_JMP:
            pc = prog[pc];
            break;

        case OP_MOV:
            vm->i = 0;
            push(vm, 0);
            break;

        case OP_LOADI:
            push(vm, vm->i);
            break;

        case OP_GETBYTE:
            push(vm, (unsigned char)vm->input[vm->i]);
            break;

        case OP_GETKEY:
            push(vm, (unsigned char)vm->buf[0][vm->i]);
            break;

        case OP_XORI: {
            int imm = prog[pc++];
            int v = pop(vm);
            push(vm, v ^ imm);
            break;
        }

        case OP_INC:
            vm->i++;
            break;

        case OP_LOADK:
            push(vm, prog[pc++]);
            break;

        case OP_RET:
            return pop(vm);

        case OP_HALT:
            return 0;

        default:
            return 0;   /* 未知操作码 */
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    static VM vm;
    memset(&vm, 0, sizeof(vm));

    if (argc < 2) {
        printf("usage: target <serial>\n");
        return 2;
    }

    /* 输入拷进 VM 的缓冲区（长度受限） */
    strncpy(vm.input, argv[1], MAXLEN - 1);
    vm.input[MAXLEN - 1] = 0;

    int ok = vm_run(PROGRAM, (int)sizeof(PROGRAM), &vm);

    if (ok) {
        printf("%s\n", vm.buf[1]);   /* ok 串 */
        return 0;
    }
    printf("%s\n", vm.buf[2]);       /* bad 串 */
    return 1;
}
