#!/usr/bin/env node
/**
 * REA 反制评分器 —— 用「对手能还原出多少秘密」来度量加固效果。
 *
 * 设计原则：
 *   朴素指标（confidence 分布、观测纯度）衡量的是 REA 自己有多确信，
 *   与「对手能否复刻」无关。真正该测的是秘密泄漏面。
 *
 * 四项核心指标（全部只看「内容里有没有」）：
 *   key_leak      密钥明文出现在任一工具输出中
 *   ok_leak       成功串明文出现
 *   fail_leak     失败串明文出现
 *   algo_leak     伪代码里出现算法指纹（异或立即数 / 滚动密钥累加 / 循环比较结构）
 *
 * 用法：
 *   node score.mjs <raw.jsonl>              单样本评分
 *   node score.mjs --diff a.raw.jsonl b.raw.jsonl   加固前后对比
 */

import { readFileSync } from "node:fs";

const SECRETS = {
  key_leak: "REA-TARGET-2026",
  ok_leak: "LICENSE_OK: access granted",
  fail_leak: "LICENSE_FAIL: invalid serial",
};

/**
 * 算法指纹：命中的越多，说明「解密/校验逻辑」暴露得越彻底。
 *
 * 注意 rolling_key 的精确化：`X ^ bVar1`（寄存器异或寄存器）不是滚动密钥，
 * 只有「立即数累加」`+ 0x..` 直接作用在密钥变量上才算。
 * 早期用 `\+\s*0x..` 会把 VM 的 `local_88 + 2`（pc 前进）误判成密钥滚动，
 * 而 +2/+1 恰恰是操作码步长，属于误报来源。
 */
const ALGO_FINGERPRINTS = [
  { id: "xor_immediate", re: /\^\s*0x[0-9a-f]{1,4}U?\b/i, label: "异或立即数" },
  { id: "rolling_key", re: /(?:key|seed|local_1[0-9a-f])\w*\s*(?:\+|\+=)\s*(?:0x[0-9a-f]{1,2}U?|cVar\d|bVar\d)/i, label: "密钥滚动累加" },
  { id: "byte_compare_loop", re: /while\s*\(\s*true\s*\)[\s\S]{0,400}==/i, label: "循环内逐字节比较" },
  { id: "strlen_call", re: /strlen\s*\(/i, label: "长度前置校验" },
  { id: "key_index", re: /\[local_\w+\]\s*==\s*\*?\(?\w*\s*\*?\)?\s*\(?\w+\[/i, label: "密钥表索引比较" },
  // 虚拟化指纹：Ghidra 读出「按字节分派的 switch」，说明解释器语义已暴露
  { id: "vm_dispatch", re: /switch\s*\(\s*\*?\(?char\s*\*?\)?\s*\([^)]*\+[^)]*\)\s*\)/i, label: "字节码分派 switch" },
  // 虚拟化指纹：伪代码里出现「间接操作码表」形态（把 prog[pc] 当函数指针/查表）
  { id: "vm_table", re: /case\s+-\s*0x[0-9a-f]{1,2}\s*:/i, label: "操作码负字面量分派" },
];

/** 读取探针原始留档，抽出每个工具的 Evidence 信封 */
function loadEvidence(path) {
  const lines = readFileSync(path, "utf8").trim().split("\n").filter(Boolean);
  const out = [];
  for (const line of lines) {
    let m;
    try {
      m = JSON.parse(line);
    } catch {
      continue;
    }
    const content = m?.result?.content;
    if (!Array.isArray(content)) continue;
    let env;
    try {
      env = JSON.parse(content.map((p) => p.text ?? "").join(""));
    } catch {
      continue;
    }
    if (!env?.evidence_id) continue;
    out.push(env);
  }
  return out;
}

/** 把一个 Evidence 信封「摊平」成可搜索的文本（含 normalized_result 与 raw_result） */
function flatten(env) {
  const parts = [];
  const walk = (v, depth) => {
    if (depth > 12 || v == null) return;
    if (typeof v === "string") {
      parts.push(v);
      return;
    }
    if (typeof v === "number" || typeof v === "boolean") return;
    if (Array.isArray(v)) {
      for (const x of v) walk(x, depth + 1);
      return;
    }
    if (typeof v === "object") {
      for (const x of Object.values(v)) walk(x, depth + 1);
    }
  };
  walk(env.normalized_result, 0);
  walk(env.raw_result, 0);
  return parts.join("\n");
}

/** 对一个样本打分 */
function score(path) {
  const evidence = loadEvidence(path);
  const blob = evidence.map(flatten).join("\n");

  const leaks = {};
  for (const [id, secret] of Object.entries(SECRETS)) {
    leaks[id] = blob.includes(secret) ? 1 : 0;
  }

  // 伪代码单独取，因为算法指纹只在伪代码里有意义
  const afEnvs = evidence.filter((e) => e.operation === "analyze_function");
  const pseudo = afEnvs
    .map((e) => e?.normalized_result?.pseudocode ?? "")
    .filter((s) => typeof s === "string")
    .join("\n");

  const algoHits = ALGO_FINGERPRINTS.filter((f) => f.re.test(pseudo)).map((f) => f.id);

  // 字符串清单里还能看到多少条业务相关串
  const strEnvs = evidence.filter((e) => e.operation === "list_strings");
  const allStrings = strEnvs.flatMap((e) => (Array.isArray(e.normalized_result) ? e.normalized_result : []));
  const bizStrings = allStrings.filter((x) =>
    /REA-TARGET|LICENSE|serial|access granted|invalid/i.test(String(x?.value ?? ""))
  ).length;

  // 单函数反编译质量：伪代码长度 + 被引用字符串数
  const pseudoLen = pseudo.length;
  const refStrings = afEnvs.reduce(
    (n, e) => n + (Array.isArray(e?.normalized_result?.referenced_strings) ? e.normalized_result.referenced_strings.length : 0),
    0
  );

  // 解释器暴露度：命中 vm_dispatch / vm_table 说明对手能读到操作码语义
  const vmFingerprints = algoHits.filter((x) => x === "vm_dispatch" || x === "vm_table");
  // 真正的「业务逻辑指纹」：排除虚拟化指纹后的算法命中
  const logicFingerprints = algoHits.filter((x) => x !== "vm_dispatch" && x !== "vm_table");

  /*
   * ══════════════════════════════════════════════════════════════════
   * 复刻成本模型（这是整个评分器的核心，别再退回「数指纹」）
   * ══════════════════════════════════════════════════════════════════
   *
   * 前两版评分器的根本错误：把「指纹个数」当作暴露度。它无法区分：
   *
   *   ① 明文直接可读         → 成本 0，复制粘贴
   *   ② 解密函数伪代码可读   → 成本低，把 decode() 抄下来离线跑一遍即可
   *                             （A1 的情况：local_18 = A^B; local_18 += cVar1）
   *   ③ 逻辑压进解释器       → 成本高，得到的是「一台机器」，
   *                             对手必须自己写执行器才能取到秘密
   *                             （A4 的情况：3904 字 switch，17 个操作码）
   *   ④ 连解释器也看不出语义 → 成本极高（本轮未实现）
   *
   * 因此分数 = 取得「三个秘密串」所需的最小可自动化程度，而不是特征计数。
   * 只有①②是可自动化路径；③必须人工理解语义后手写工具。
   */

  // ---- 第 1 层：明文是否在文件/证据里直接可读（成本 0）
  const plainLeak = (leaks.key_leak + leaks.ok_leak + leaks.fail_leak) / 3; // 0..1

  // ---- 第 2 层：是否存在「可离线复用的解密/校验函数」
  //     判据不是有没有 xor，而是 xor 是否作用在「可读的常量/数组」上且
  //     伪代码里能看到完整的加密循环（含累加/索引推进）
  const hasDecryptLoop =
    /xor_immediate/.test(algoHits.join(",")) &&
    (/rolling_key/.test(algoHits.join(",")) || /byte_compare_loop/.test(algoHits.join(",")));

  // ---- 第 3 层：逻辑是否被虚拟化（switch 分派 + 多操作码）
  const isVirtualized = vmFingerprints.length > 0;

  /*
   * ---- 第 4 层：字节码是否需要「运行期还原」才能解析
   *
   * 这是 A5 相对 A4 的唯一实质差异，必须单独计量，否则两者同分。
   *
   *   A4 形态：switch(*(char *)(param_1 + pc))          字节值 == 操作码，读文件即用
   *   A5 形态：switch(param_3[byte + 0x148])             字节 -> inv[] -> 操作码
   *
   * 判据：switch 的参数表达式里出现「二次索引」——
   *   即先取一个字节，再用它当作下标去查另一个数组（形如 X[Y[i] + off]）。
   * 这种形态下，静态读到的字节码不能直接用，必须先跑一遍密钥派生。
   */
  const dispatchLine = (pseudo.split("\n").find((l) => /switch\s*\(/.test(l)) ?? "");
  const needsRuntimeDecode =
    /\[\s*[^\]\[]*\[[^\]]+\][^\]]*\]/.test(dispatchLine) ||   // X[Y[i]...] 二次索引
    /\+\s*0x1[0-9a-f]{2}\s*\]\s*\)\s*\{/.test(dispatchLine); // 逆表固定偏移形态

  /*
   * 最终复刻度：
   *   明文泄漏直接封顶（有明文就是满分暴露，加固没起作用）
   *   有可离线复用的解密循环 → 70 分基线（抄函数就能解）
   *   已虚拟化且无明文        → 30 分基线（要手工还原语义）
   *   虚拟化 + 需运行期还原    → 再降 10（连字节码都要先跑派生）
   */
  let replica;
  if (plainLeak > 0) {
    // 明文在：无论多少加固，都是暴露。泄漏越多分越高
    replica = 70 + Math.round(plainLeak * 30);
  } else if (isVirtualized) {
    replica = 30 + (hasDecryptLoop ? 8 : 0);
    if (needsRuntimeDecode) replica -= 10;   // A5：字节码要先跑派生才能解析
    replica += Math.min(Math.floor(pseudoLen / 2000) * 2, 6);
  } else {
    // 无明文但未虚拟化：核心逻辑以原生伪代码形式存在，抄下来就能跑
    replica = hasDecryptLoop ? 72 : 55;
    replica += Math.min(logicFingerprints.length * 3, 12);
  }
  replica = Math.max(0, Math.min(100, replica));

  return {
    file: path,
    secrets: leaks,
    algo_fingerprints: algoHits,
    logic_fingerprints: logicFingerprints,
    vm_fingerprints: vmFingerprints,
    needs_runtime_decode: needsRuntimeDecode,
    biz_strings_visible: bizStrings,
    pseudocode_length: pseudoLen,
    referenced_strings: refStrings,
    replica_score: replica,
  };
}

const argv = process.argv.slice(2);
if (argv[0] === "--diff") {
  const a = score(argv[1]);
  const b = score(argv[2]);
  const rows = [
    ["密钥明文泄漏 (key_leak)", a.secrets.key_leak, b.secrets.key_leak, "越低越好"],
    ["成功串泄漏 (ok_leak)", a.secrets.ok_leak, b.secrets.ok_leak, "越低越好"],
    ["失败串泄漏 (fail_leak)", a.secrets.fail_leak, b.secrets.fail_leak, "越低越好"],
    ["业务字符串可见数", a.biz_strings_visible, b.biz_strings_visible, "越低越好"],
    ["算法指纹命中数", a.algo_fingerprints.length, b.algo_fingerprints.length, "越低越好"],
    ["伪代码长度", a.pseudocode_length, b.pseudocode_length, "参考值"],
    ["被引用字符串数", a.referenced_strings, b.referenced_strings, "越低越好"],
    ["复刻综合分", a.replica_score, b.replica_score, "越低越好"],
  ];
  const w = 28;
  console.log("═".repeat(74));
  console.log(" 加固前后 · 秘密泄漏面差分");
  console.log("═".repeat(74));
  console.log(" 指标".padEnd(w) + "加固前 → 加固后".padEnd(20) + "说明");
  console.log(" " + "─".repeat(72));
  for (const [name, x, y] of rows) {
    const delta = y - x;
    const mark = delta < 0 ? "↓" : delta > 0 ? "↑" : "=";
    console.log(
      " " + name.padEnd(w - 1) + `${String(x).padEnd(6)}→ ${String(y).padEnd(6)}${mark}`.padEnd(20) + rows.find((r) => r[0] === name)[3]
    );
  }
  console.log(" " + "─".repeat(72));
  console.log(` 算法指纹明细（加固前）: ${a.algo_fingerprints.join(", ") || "无"}`);
  console.log(` 算法指纹明细（加固后）: ${b.algo_fingerprints.join(", ") || "无"}`);
  const verdict =
    b.replica_score <= a.replica_score - 25
      ? "✅ 有效：复刻度显著下降"
      : b.replica_score < a.replica_score
      ? "△ 部分有效：有下降但不够"
      : "❌ 无效：复刻度未下降";
  console.log(`\n 判定：${verdict}  (${a.replica_score} → ${b.replica_score})`);
} else if (argv[0]) {
  console.log(JSON.stringify(score(argv[0]), null, 2));
} else {
  console.log("用法: node score.mjs <raw.jsonl> | node score.mjs --diff <before> <after>");
  process.exit(2);
}
