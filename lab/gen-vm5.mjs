// A5 字节码生成器：在 JS 里复现 C 侧的 derive_seed / build_perm / unpack_program，
// 生成加密+置换后的字节码数组，直接粘进 target-vm5.c。
//
// 为什么必须在 JS 里算：C 侧 perm 依赖运行期 seed，而 seed 依赖编译期常量。
// 两边只要有一处不一致，运行就会静默走失败分支（A4 已经踩过一次栈泄漏的坑，
// 这次不靠肉眼核对，靠脚本双向验证）。

import { writeFileSync } from "node:fs";

/* ---------- A1 密文数组（与 target-vm5.c 必须逐字节一致） ---------- */
const ENC_KEY = [
  0x59, 0x4b, 0x50, 0x39, 0x43, 0x5b, 0x4f, 0x67, 0x66, 0x72, 0x04, 0x1e, 0x1f, 0x00, 0x03, 0x38,
];
const ENC_OK = [
  0x47, 0x47, 0x52, 0x51, 0x59, 0x49, 0x58, 0x7f, 0x6c, 0x6d, 0x13, 0x0c, 0x4e,
  0x51, 0x56, 0x5d, 0x48, 0x4d, 0x61, 0x23, 0x35, 0x2b, 0x23, 0x24, 0x36, 0x32, 0x59,
];
const ENC_BAD = [
  0x47, 0x47, 0x52, 0x51, 0x59, 0x49, 0x58, 0x7f, 0x65, 0x67, 0x60, 0x60, 0x15, 0x12, 0x5c,
  0x56, 0x4d, 0x5f, 0x2d, 0x2d, 0x23, 0x6a, 0x3e, 0x35, 0x21, 0x3f, 0x38, 0x30, 0x5f,
];

/* ---------- VM 真实操作码 ---------- */
const OP = {
  HALT: 0x00, LOADK: 0x11, DECRYPT: 0x22, STRLEN: 0x33,
  CMP: 0x44, JZ: 0x55, MOV: 0x66, GETBYTE: 0x77,
  GETKEY: 0x88, XORI: 0x99, INC: 0xaa, JMP: 0xbb,
  RET: 0xcc, LOADI: 0xdd, EQ: 0xee, JNZ: 0xff,
};

/* ---------- 明文程序（与 C 注释里的布局逐字节对应） ---------- */
const PROGRAM = [
  OP.DECRYPT, 0x00,        // 0x00
  OP.DECRYPT, 0x01,        // 0x02
  OP.DECRYPT, 0x02,        // 0x04
  OP.STRLEN, 0x01,         // 0x06
  OP.STRLEN, 0x02,         // 0x08
  OP.EQ,                   // 0x0a
  OP.JZ, 0x23,             // 0x0b -> bad
  OP.MOV,                  // 0x0d
  OP.LOADI,                // 0x0e  loop
  OP.STRLEN, 0x01,         // 0x0f
  OP.CMP,                  // 0x11
  OP.JZ, 0x20,             // 0x12 -> ok
  OP.GETBYTE,              // 0x14
  OP.XORI, 0x37,           // 0x15
  OP.XORI, 0x6d,           // 0x17 合计 ^0x5A
  OP.GETKEY,               // 0x19
  OP.EQ,                   // 0x1a
  OP.JZ, 0x23,             // 0x1b -> bad
  OP.INC,                  // 0x1d
  OP.JMP, 0x0e,            // 0x1e
  OP.LOADK, 0x01,          // 0x20 ok
  OP.RET,                  // 0x22
  OP.LOADK, 0x00,          // 0x23 bad
  OP.RET,                  // 0x25
  OP.HALT,                 // 0x26
];

/* ---------- C 侧同款运算（必须逐位一致） ---------- */
const u32 = (x) => x >>> 0;

function xorshift(s) {
  s = u32(s);
  s = u32(s ^ (s << 13));
  s = u32(s ^ (s >>> 17));
  s = u32(s ^ (s << 5));
  return s;
}

function deriveSeed() {
  let s = u32(0x9e3779b9);
  s = u32(s ^ u32(ENC_KEY.length * 0x01000193));
  s = u32(s + u32(ENC_BAD.length << 7));
  s = u32(s ^ u32(ENC_OK[0] << 16));
  s = u32(s ^ u32(ENC_KEY[1] << 8));
  s = u32(s ^ 0x5bf03635);
  for (let r = 0; r < 4; r++) s = xorshift(s);
  return s === 0 ? 1 : s;
}

function buildPerm(seed) {
  const idx = new Uint8Array(256);
  for (let i = 0; i < 256; i++) idx[i] = i;
  let x = u32(seed);
  for (let i = 255; i > 0; i--) {
    x = xorshift(x);
    const j = x % (i + 1);
    const t = idx[i];
    idx[i] = idx[j];
    idx[j] = t;
  }
  return idx; // perm[real] = shuffled
}

function packProgram(plain, seed) {
  const perm = buildPerm(seed);
  // 第一步：真实操作码 -> 置换像。注意只有「操作码位置」需要置换，
  // 立即数（参数）保持原值，否则解释器读参数时会错位。
  const shuffled = new Uint8Array(plain.length);
  for (let i = 0; i < plain.length; i++) shuffled[i] = perm[plain[i]];

  // 注意：严格来说必须区分「哪个位置是操作码、哪个是立即数」。
  // 这里为了不把解析器搬进生成器，采用一个更强的约定：
  // 只置换「pc 恰好指向操作码」的那些位置，由下面的 opcodeMask 决定。

  // 第二步：整体异或流加密（与 C 的 unpack_program 一致）
  let x = u32(seed ^ 0xa5a5a5a5);
  const enc = new Uint8Array(plain.length + 1);
  enc[0] = plain.length;
  for (let i = 0; i < plain.length; i++) {
    x = xorshift(x);
    enc[i + 1] = (shuffled[i] ^ ((x >>> 3) & 0xff)) & 0xff;
  }
  return enc;
}

/*
 * 严格版：只有操作码字节需要置换。
 * 立即数不置换——解释器读参数时是 prog[pc++]，拿到的就是原值。
 * 因此必须先静态走一遍程序，标出哪些偏移是操作码。
 */
function opcodeMask(plain) {
  const mask = new Uint8Array(plain.length);
  let pc = 0;
  const operandLen = {
    [OP.LOADK]: 1, [OP.DECRYPT]: 1, [OP.STRLEN]: 1, [OP.JZ]: 1,
    [OP.JNZ]: 1, [OP.JMP]: 1, [OP.XORI]: 1,
  };
  while (pc < plain.length) {
    const op = plain[pc];
    mask[pc] = 1;
    pc += 1 + (operandLen[op] ?? 0);
  }
  return mask;
}

function packStrict(plain, seed) {
  const perm = buildPerm(seed);
  const mask = opcodeMask(plain);
  const shuffled = new Uint8Array(plain.length);
  for (let i = 0; i < plain.length; i++) {
    shuffled[i] = mask[i] ? perm[plain[i]] : plain[i];
  }
  let x = u32(seed ^ 0xa5a5a5a5);
  const enc = new Uint8Array(plain.length + 1);
  enc[0] = plain.length;
  for (let i = 0; i < plain.length; i++) {
    x = xorshift(x);
    enc[i + 1] = (shuffled[i] ^ ((x >>> 3) & 0xff)) & 0xff;
  }
  return { enc, mask, shuffled };
}

/* ---------- 生成并自检 ---------- */
const seed = deriveSeed();
const { enc, mask, shuffled } = packStrict(PROGRAM, seed);

// 自检：模拟 C 侧 unpack + inv 还原，验证能拿回原始程序
const perm = buildPerm(seed);
const inv = new Uint8Array(256);
for (let r = 0; r < 256; r++) inv[perm[r]] = r;

const restored = new Uint8Array(enc[0]);
let x = u32(seed ^ 0xa5a5a5a5);
for (let i = 0; i < enc[0]; i++) {
  x = xorshift(x);
  restored[i] = (enc[i + 1] ^ ((x >>> 3) & 0xff)) & 0xff;
}
// 解释器每步只对「操作码位置」做 inv 还原——但解释器并不知道 mask，
// 它是在 pc 指向操作码时执行 inv[raw]。而参数位置是 prog[pc++] 直读，不还原。
// 所以 restored 里参数位置应当原样、操作码位置应当是 shuffled 像。
// 用 mask 把操作码位置还原回真实值再比对。
const back = new Uint8Array(restored.length);
const m2 = opcodeMask(PROGRAM);
let okAll = true;
for (let i = 0; i < restored.length; i++) {
  back[i] = m2[i] ? inv[restored[i]] : restored[i];
  if (back[i] !== PROGRAM[i]) okAll = false;
}

console.log("seed = 0x" + seed.toString(16).padStart(8, "0"));
console.log("程序长度 =", PROGRAM.length, "字节");
console.log("置换后字节码与明文是否不同:", shuffled.join(",") !== Uint8Array.from(PROGRAM).join(","));
console.log("逆变换还原是否完全正确:", okAll ? "✅" : "❌ 有偏差");
if (!okAll) {
  for (let i = 0; i < PROGRAM.length; i++) {
    if (back[i] !== PROGRAM[i]) {
      console.log("  偏差 @" + i, "期望", PROGRAM[i].toString(16), "实得", back[i].toString(16), "mask", m2[i]);
    }
  }
}

// 输出 C 数组
const hex = Array.from(enc).map((b) => "0x" + b.toString(16).padStart(2, "0"));
const lines = [];
for (let i = 0; i < hex.length; i += 12) lines.push("    " + hex.slice(i, i + 12).join(", "));
const cArray = "static const unsigned char PROGRAM_ENC[] = {\n" + lines.join(",\n") + "\n};";

console.log("\n" + cArray);

writeFileSync("program_enc.txt", cArray + "\n", "utf8");
console.log("\n已写入 program_enc.txt");
