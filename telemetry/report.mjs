#!/usr/bin/env node
/**
 * REA Tap 观测报告器
 *
 * 把 rea-tap.mjs 产出的 NDJSON 汇总成人类可读的「REA 看见了什么」报表。
 * 这是 A 路线（样本加固）的评分器：加固前后各跑一次，比 observed/unknown 比。
 *
 * 用法：
 *   node report.mjs                     # 自动找最新的 rea-tap-*.ndjson
 *   node report.mjs <log.ndjson>        # 指定文件
 *   node report.mjs --json              # 输出 JSON（给脚本消费）
 *   node report.mjs --compare a.ndjson b.ndjson   # 加固前后对比
 */

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);

const loadLog = (path) =>
  readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    })
    .filter(Boolean);

const findLatest = () => {
  const files = readdirSync(HERE)
    .filter((f) => /^rea-tap-\d{8}\.ndjson$/.test(f))
    .sort();
  if (!files.length) throw new Error(`在 ${HERE} 未找到 rea-tap-*.ndjson`);
  return join(HERE, files[files.length - 1]);
};

/** 把一串事件折叠成统计画像 */
const summarize = (events) => {
  const calls = events.filter((e) => e.kind === "c2s_call");
  const results = events.filter((e) => e.kind === "s2c_result");

  const byTool = {};
  for (const r of results) {
    const t = (byTool[r.tool] ??= {
      n: 0, errors: 0, evidence: 0, unknowns: 0,
      authorities: {}, confidences: {}, total_ms: 0,
    });
    t.n++;
    if (r.isError) t.errors++;
    t.evidence += r.evidenceCount ?? 0;
    t.unknowns += r.unknowns ?? 0;
    t.total_ms += r.duration_ms ?? 0;
    for (const [k, v] of Object.entries(r.authorities ?? {})) t.authorities[k] = (t.authorities[k] ?? 0) + v;
    for (const [k, v] of Object.entries(r.confidences ?? {})) t.confidences[k] = (t.confidences[k] ?? 0) + v;
  }

  const tot = { calls: calls.length, results: results.length, errors: 0, evidence: 0, unknowns: 0,
                authorities: {}, confidences: {}, ms: 0 };
  for (const t of Object.values(byTool)) {
    tot.errors += t.errors; tot.evidence += t.evidence; tot.unknowns += t.unknowns; tot.ms += t.total_ms;
    for (const [k, v] of Object.entries(t.authorities)) tot.authorities[k] = (tot.authorities[k] ?? 0) + v;
    for (const [k, v] of Object.entries(t.confidences)) tot.confidences[k] = (tot.confidences[k] ?? 0) + v;
  }

  // 观测纯度：observed 在全部 confidence 中的占比
  const cTotal = Object.values(tot.confidences).reduce((a, b) => a + b, 0);
  const observed = tot.confidences.observed ?? 0;
  const purity = cTotal > 0 ? observed / cTotal : null;

  return { byTool, tot, purity, start: events.find((e) => e.kind === "tap_start") };
};

const bar = (v, w = 24) => {
  const n = Math.max(0, Math.min(w, Math.round(v * w)));
  return "█".repeat(n) + "░".repeat(w - n);
};

const render = (s, label) => {
  const L = [];
  L.push(`\n${"═".repeat(66)}`);
  L.push(` REA 观测报告 ${label ? `— ${label}` : ""}`);
  L.push(`${"═".repeat(66)}`);

  const st = s.start;
  if (st) {
    L.push(` 观测开始 : ${st.ts}`);
    L.push(` REA 命令 : ${st.childCmd} ${(st.childArgs ?? []).join(" ")}`);
    L.push(` 改写钩子 : ${st.mutate ? "开启" : "关闭（透明）"}`);
  }

  L.push(`\n 调用总数 : ${s.tot.calls}  (结果 ${s.tot.results}, 错误 ${s.tot.errors})`);
  L.push(` 证据条数 : ${s.tot.evidence}`);
  L.push(` 未知项   : ${s.tot.unknowns}`);
  L.push(` 累计耗时 : ${s.tot.ms} ms`);

  if (s.purity !== null) {
    L.push(`\n 观测纯度 : ${(s.purity * 100).toFixed(1)}%   ${bar(s.purity)}`);
    L.push(`            (observed 占全部 confidence 标注的比例, 越高=REA 看得越清)`);
  } else {
    L.push(`\n 观测纯度 : 无数据（本批调用未返回 confidence 标注）`);
  }

  const conf = Object.entries(s.tot.confidences).sort((a, b) => b[1] - a[1]);
  if (conf.length) {
    L.push(`\n 置信度分布:`);
    for (const [k, v] of conf) L.push(`   ${k.padEnd(10)} ${String(v).padStart(5)}`);
  }
  const auth = Object.entries(s.tot.authorities).sort((a, b) => b[1] - a[1]);
  if (auth.length) {
    L.push(`\n 权威来源分布:`);
    for (const [k, v] of auth) L.push(`   ${k.padEnd(22)} ${String(v).padStart(5)}`);
  }

  const tools = Object.entries(s.byTool).sort((a, b) => b[1].n - a[1].n);
  if (tools.length) {
    L.push(`\n 按工具:`);
    L.push(`   ${"工具".padEnd(34)}${"次".padStart(4)}${"错".padStart(4)}${"证据".padStart(6)}${"未知".padStart(6)}${"ms".padStart(8)}`);
    for (const [k, t] of tools.slice(0, 30)) {
      L.push(`   ${k.padEnd(34)}${String(t.n).padStart(4)}${String(t.errors).padStart(4)}${String(t.evidence).padStart(6)}${String(t.unknowns).padStart(6)}${String(t.total_ms).padStart(8)}`);
    }
    if (tools.length > 30) L.push(`   ... 另有 ${tools.length - 30} 个工具`);
  }

  L.push("");
  return L.join("\n");
};

// ---------- 主流程 ----------
const main = () => {
  const jsonOut = argv.includes("--json");
  const cmpIdx = argv.indexOf("--compare");

  if (cmpIdx !== -1) {
    const [a, b] = argv.slice(cmpIdx + 1, cmpIdx + 3);
    if (!a || !b) throw new Error("--compare 需要两个日志路径");
    const A = summarize(loadLog(resolve(a)));
    const B = summarize(loadLog(resolve(b)));
    console.log(render(A, `基线 ${resolve(a)}`));
    console.log(render(B, `对照 ${resolve(b)}`));
    console.log(`${"═".repeat(66)}\n 差分\n${"═".repeat(66)}`);
    const d = (x, y) => {
      const v = y - x;
      const sign = v > 0 ? "+" : "";
      return `${x} → ${y}  (${sign}${v})`;
    };
    console.log(` 证据条数 : ${d(A.tot.evidence, B.tot.evidence)}`);
    console.log(` 未知项   : ${d(A.tot.unknowns, B.tot.unknowns)}`);
    console.log(` 错误数   : ${d(A.tot.errors, B.tot.errors)}`);
    if (A.purity !== null && B.purity !== null) {
      console.log(` 观测纯度 : ${(A.purity * 100).toFixed(1)}% → ${(B.purity * 100).toFixed(1)}%` +
        `  (${B.purity >= A.purity ? "+" : ""}${((B.purity - A.purity) * 100).toFixed(1)}pp)`);
      console.log(B.purity < A.purity
        ? `\n ⇒ 对照组的观测纯度更低：加固方向有效。`
        : `\n ⇒ 对照组未见劣化：该加固对手法无效，需要换手法。`);
    }
    return;
  }

  const target = argv.find((a) => !a.startsWith("--"));
  const path = target ? resolve(target) : findLatest();
  if (!existsSync(path)) throw new Error(`文件不存在: ${path}`);
  const s = summarize(loadLog(path));
  if (jsonOut) console.log(JSON.stringify({ path, ...s }, null, 2));
  else console.log(render(s, path));
};

try { main(); } catch (e) { console.error(`report: ${e.message}`); process.exit(1); }
