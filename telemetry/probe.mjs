#!/usr/bin/env node
/**
 * REA 基线探针 —— 让 REA 对指定目标跑一套标准分析动作，
 * 并统计它「看穿了多少」。通过 rea-tap 代理，所有 Evidence 落盘。
 *
 * 用法：
 *   node probe.mjs <目标路径> [日志名]
 *
 * 分析动作（固定顺序，保证可复现）：
 *   1. open_binary          打开目标
 *   2. binary_overview      段/符号/字符串计数
 *   3. list_strings         抽全部字符串
 *   4. search_strings       搜特征串（LICENSE）
 *   5. search_strings       搜特征串（REA-TARGET）
 *   6. list_procedures      函数清单
 *   7. analyze_function     对 main 做完整档案（先解析真实函数名）
 *
 * 输出：telemetry/<日志名>.ndjson，供 report.mjs 汇总
 */

import { spawn } from "node:child_process";
import { existsSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

const targetArg = process.argv[2];
if (!targetArg) {
  console.error("用法: node probe.mjs <目标路径> [日志名]");
  process.exit(2);
}
const TARGET = resolve(targetArg);
if (!existsSync(TARGET)) {
  console.error(`目标不存在: ${TARGET}`);
  process.exit(2);
}
const LOG_NAME = process.argv[3] ?? "probe";
const LOG = resolve(HERE, `${LOG_NAME}.ndjson`);
const RAW = resolve(HERE, `${LOG_NAME}.raw.jsonl`); // 原始 JSON-RPC 全量留档
if (existsSync(LOG)) rmSync(LOG);
if (existsSync(RAW)) rmSync(RAW);

// 逆向工具的 MCP 启动命令。用环境变量注入，避免把任何本机路径写进仓库。
if (!process.env.REA_CMD) {
  console.error("缺少环境变量 REA_CMD。");
  console.error('示例：REA_CMD="node /path/to/reverse-tool.mjs mcp" node probe.mjs target.exe');
  process.exit(1);
}
const CMD = process.env.REA_CMD.split(/\s+/).filter(Boolean);
const NODE = process.execPath;

const tap = spawn(NODE, [`${HERE}/rea-tap.mjs`, "--", ...CMD], {
  stdio: ["pipe", "pipe", "pipe"],
  env: { ...process.env, REA_TAP_LOG: LOG },
});

// ---------- 干净的单一路径行解析 ----------
let buf = "";
const waiters = new Map();
const rawLog = [];

tap.stdout.on("data", (chunk) => {
  buf += chunk.toString("utf8");
  let i;
  while ((i = buf.indexOf("\n")) !== -1) {
    const line = buf.slice(0, i).replace(/\r$/, "");
    buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    let m;
    try {
      m = JSON.parse(line);
    } catch {
      continue;
    }
    rawLog.push(m);
    if (m.id !== undefined && waiters.has(m.id)) {
      const w = waiters.get(m.id);
      waiters.delete(m.id);
      w.resolve(m);
    }
  }
});

let stderrBuf = "";
tap.stderr.on("data", (d) => {
  stderrBuf += d.toString("utf8");
  if (stderrBuf.length > 200_000) stderrBuf = stderrBuf.slice(-100_000);
});

let nextId = 1;

/** 发一个 JSON-RPC 请求并等它的 response（按 id 精确匹配，带超时） */
const rpc = (method, params, timeoutMs = 300_000) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => {
      waiters.delete(id);
      reject(new Error(`RPC ${method} 超时 (${timeoutMs}ms)`));
    }, timeoutMs);
    waiters.set(id, {
      resolve: (m) => {
        clearTimeout(timer);
        resolve(m);
      },
    });
    tap.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });

/** 工具调用：包一层 tools/call */
const call = (name, args, timeoutMs = 300_000) =>
  rpc("tools/call", { name, arguments: args }, timeoutMs);

/** 从工具响应里取结构化对象 */
const structured = (resp) => {
  const c = resp?.result?.content;
  if (!Array.isArray(c)) return null;
  for (const part of c) {
    if (part?.type === "text" && typeof part.text === "string") {
      try {
        return JSON.parse(part.text);
      } catch {
        return { __text: part.text };
      }
    }
  }
  return null;
};

const summarize = (resp) => {
  if (resp?.error) return `RPC错误: ${JSON.stringify(resp.error).slice(0, 300)}`;
  const r = resp?.result;
  if (r?.isError) {
    const s = structured(resp);
    const e = s?.error ?? {};
    return `工具错误: ${e.code ?? "?"} — ${String(e.message ?? "").slice(0, 200)}`;
  }
  const s = structured(resp);
  if (!s) return "（无结构化 payload）";
  const bits = [];
  if (s.evidence_id) bits.push(`ev=${s.evidence_id.slice(0, 12)}…`);
  if (s.confidence) bits.push(`conf=${s.confidence}`);
  if (s.authority) bits.push(`auth=${s.authority}`);
  const json = JSON.stringify(s);
  bits.push(`${json.length} bytes`);
  return bits.join("  ") + `  |  ${json.slice(0, 180).replace(/\s+/g, " ")}`;
};

const run = async () => {
  console.log(`╔ 目标 : ${TARGET}`);
  console.log(`║ 日志 : ${LOG}`);
  console.log(`╚ 原始 : ${RAW}\n`);

  // 1) 握手
  const init = await rpc("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "rea-probe", version: "1.0.0" },
  });
  console.log(`initialize → ${init.result?.serverInfo?.name} v${init.result?.serverInfo?.version}  (协议 ${init.result?.protocolVersion})\n`);
  tap.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized", params: {} }) + "\n");

  // 2) open_binary
  process.stdout.write("→ open_binary\n");
  const opened = await call("open_binary", { path: TARGET }, 300_000);
  console.log(`   ${summarize(opened)}\n`);

  // 3) binary_overview（Ghidra 首分析，慢）
  process.stdout.write("→ binary_overview （Ghidra 首次分析，请稍候）\n");
  const tOv = Date.now();
  const ov = await call("binary_overview", {}, 900_000);
  console.log(`   ${((Date.now() - tOv) / 1000).toFixed(1)}s  ${summarize(ov)}\n`);

  // 4) list_strings
  process.stdout.write("→ list_strings\n");
  const strs = await call("list_strings", {}, 300_000);
  const strObj = structured(strs);
  const strCount = Array.isArray(strObj?.items) ? strObj.items.length
                 : Array.isArray(strObj?.strings) ? strObj.strings.length
                 : Array.isArray(strObj) ? strObj.length : null;
  console.log(`   ${summarize(strs)}${strCount !== null ? `  [字符串 ${strCount} 条]` : ""}\n`);

  // 5) search_strings x2
  for (const pat of ["LICENSE", "REA-TARGET"]) {
    process.stdout.write(`→ search_strings("${pat}")\n`);
    const r = await call("search_strings", { pattern: pat, mode: "literal", case_sensitive: false }, 120_000);
    const o = structured(r);
    const hit = o?.matches?.length ?? o?.items?.length ?? (Array.isArray(o) ? o.length : "?");
    console.log(`   命中 ${hit}  ${summarize(r)}\n`);
  }

  // 6) list_procedures
  //    真实结构：{evidence_id, ..., normalized_result: [{address, value, procedure:{external,thunk,...}}]}
  process.stdout.write("→ list_procedures\n");
  const procs = await call("list_procedures", {}, 300_000);
  const procEnv = structured(procs);
  const procList = Array.isArray(procEnv?.normalized_result) ? procEnv.normalized_result
                 : Array.isArray(procEnv?.raw_result) ? procEnv.raw_result
                 : Array.isArray(procEnv) ? procEnv : [];
  const internal = procList.filter((p) => p?.procedure?.external !== true);
  const externals = procList.length - internal.length;
  console.log(`   函数 ${procList.length} 个（内部 ${internal.length} / 外部 ${externals}）  ${summarize(procs)}\n`);

  // 7) analyze_function —— 多函数采样
  //
  // 只分析一个函数会严重低估 REA 的穿透力：加固后的二进制把逻辑拆散到
  // 多个函数里（如 VM 版 main 只剩 dispatch，解释器在另一个函数），
  // 单点采样只见树木。
  //
  // 采样策略：按地址升序取前 N 个内部函数。
  //   - 用户代码（MSVC 静态链接）总落在 .text 最前面，CRT 在其后；
  //   - list_procedures 不返回函数体大小，无法真正按大小排序，
  //     所以用「靠前 + 足够大的 N」来保证覆盖。
  //   - 实测 A5 的 vm_run 排在第 7 位，N=4/5 会漏掉，默认给 10。
  //   - REA_PROBE_FUNCS 可覆盖。
  const targets = [];
  if (internal.length) {
    const names = internal.map((p) => p?.value ?? p?.address).filter(Boolean);
    console.log(`   （内部函数样本: ${names.slice(0, 6).join(", ")}）`);
    console.log(`   （业务函数命中: ${names.filter((n) => /check_serial|^_?main$/i.test(n)).join(", ") || "无"}）`);

    // 优先：业务函数名（如有符号）放最前，其余按地址顺序
    const named = names.filter((n) => /check_serial|^_?main$/i.test(n));
    const candidates = [...new Set([...named, ...names])].filter(
      (n) => !/^(?:CRT|scrt|FID_|__|std::|operator |_guard_|atexit|_onexit)/i.test(n)
    );
    targets.push(...candidates.slice(0, Number(process.env.REA_PROBE_FUNCS ?? 10)));
  }

  for (const pick of targets) {
    process.stdout.write(`→ analyze_function("${pick}")\n`);
    try {
      const af = await call("analyze_function", { procedure: pick }, 600_000);
      console.log(`   ${summarize(af)}\n`);
    } catch (e) {
      console.log(`   失败: ${e.message}\n`);
    }
  }
  if (!targets.length) console.log("→ analyze_function  跳过（未取到函数清单）\n");

  // 收尾
  await new Promise((r) => setTimeout(r, 1000));
  writeFileSync(RAW, rawLog.map((m) => JSON.stringify(m)).join("\n") + "\n");
  tap.kill();
  await new Promise((r) => setTimeout(r, 500));

  console.log(`✅ 探针结束`);
  console.log(`   观测日志: ${LOG}`);
  console.log(`   原始留档: ${RAW} (${rawLog.length} 条 JSON-RPC)`);
  if (stderrBuf.trim()) {
    const tail = stderrBuf.trim().split("\n").slice(-4).join("\n");
    console.log(`\nstderr 尾部:\n${tail}`);
  }
};

run().catch((e) => {
  console.error("探针异常:", e.message);
  try { writeFileSync(RAW, rawLog.map((m) => JSON.stringify(m)).join("\n") + "\n"); } catch {}
  try { tap.kill(); } catch {}
  process.exit(1);
});
