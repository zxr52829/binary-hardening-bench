#!/usr/bin/env node
/**
 * REA Tap —— MCP stdio 透明代理 / 遥测观测器
 *
 * 挂在 dsh 与 rea-agents MCP server 之间，双向转发 JSON-RPC 消息，
 * 同时把每次 tools/call 及其返回的 Evidence 落成 NDJSON。
 *
 * 设计原则：
 *   - 纯观测，默认不改一个字节（MUTATE 关闭时是字节级透明）
 *   - 不阻塞主流程：落盘失败只记 stderr，绝不断链
 *   - 记录 evidence_id 的 authority/confidence，用于量化「REA 到底看见了多少」
 *
 * 用法（作为 dsh MCP client 的 command）：
 *   node rea-tap.mjs -- <REA 原始 command> [args...]
 * 例如：
 *   node rea-tap.mjs -- node C:\...\rea-agents\scripts\rea.mjs mcp
 *
 * 环境变量：
 *   REA_TAP_LOG      日志路径（默认 ./rea-tap-YYYYMMDD.ndjson）
 *   REA_TAP_MUTATE   1 = 开启改写钩子（实验用，默认 0）
 *   REA_TAP_VERBOSE  1 = 把每次调用摘要打到 stderr
 */

import { spawn } from "node:child_process";
import { createWriteStream, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// ---------- 解析参数 ----------
const argv = process.argv.slice(2);
const sep = argv.indexOf("--");
if (sep === -1 || sep === argv.length - 1) {
  process.stderr.write(
    "rea-tap: 需要 `--` 后跟真实 REA 命令。\n" +
      "例：node rea-tap.mjs -- node /path/to/rea-agents/scripts/rea.mjs mcp\n",
  );
  process.exit(2);
}
const childCmd = argv[sep + 1];
const childArgs = argv.slice(sep + 2);

const HERE = dirname(fileURLToPath(import.meta.url));
const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
const LOG_PATH = resolve(process.env.REA_TAP_LOG ?? `${HERE}/rea-tap-${stamp}.ndjson`);
const MUTATE = process.env.REA_TAP_MUTATE === "1";
const VERBOSE = process.env.REA_TAP_VERBOSE === "1";

mkdirSync(dirname(LOG_PATH), { recursive: true });
const log = createWriteStream(LOG_PATH, { flags: "a" });

let seq = 0;
const t0 = Date.now();
const pending = new Map(); // id -> {method, params, at}

/** 绝不抛异常的落盘 */
const emit = (kind, payload) => {
  try {
    log.write(
      JSON.stringify({
        seq: ++seq,
        ts: new Date().toISOString(),
        t_ms: Date.now() - t0,
        kind,
        ...payload,
      }) + "\n",
    );
  } catch (e) {
    process.stderr.write(`rea-tap: 落盘失败 ${e?.message ?? e}\n`);
  }
};

/**
 * 从工具返回里抽取 Evidence 画像。
 * REA 的契约参考 dist/server/contractToolHandler.js：
 *   result.value -> recordEvidence(result.value) -> toEvidenceToolResult(...)
 * 所以 evidence 一定在返回体中。
 */
const profileEvidence = (obj, acc = { ids: [], authorities: {}, confidences: {}, unknowns: 0, coverage: [] }) => {
  if (obj == null || typeof obj !== "object") return acc;
  if (Array.isArray(obj)) {
    for (const v of obj) profileEvidence(v, acc);
    return acc;
  }
  for (const [k, v] of Object.entries(obj)) {
    if (k === "evidence_id" && typeof v === "string" && v.startsWith("ev_")) acc.ids.push(v);
    else if (k === "unknown_id" && typeof v === "string" && v.startsWith("unk_")) acc.unknowns++;
    else if (k === "authority" && typeof v === "string") acc.authorities[v] = (acc.authorities[v] ?? 0) + 1;
    else if (k === "confidence" && typeof v === "string" && ["observed", "derived", "inferred"].includes(v))
      acc.confidences[v] = (acc.confidences[v] ?? 0) + 1;
    // 注意：不要泛匹配 status/severity 的 observed/high/medium，
    // 那些是 finding 严重度或 coverage 状态，混入会污染纯度指标。
    else if (k === "coverage" && typeof v === "string") acc.coverage.push(v);
    if (typeof v === "object") profileEvidence(v, acc);
  }
  return acc;
};

/** 从 MCP content 里挖出结构化结果 */
const extractStructured = (msg) => {
  const c = msg?.result?.content;
  if (!Array.isArray(c)) return null;
  const out = [];
  for (const part of c) {
    if (part?.type === "text" && typeof part.text === "string") {
      try {
        out.push(JSON.parse(part.text));
      } catch {
        out.push({ __raw_text: part.text.slice(0, 4000) });
      }
    } else if (part?.type === "json" && part.json !== undefined) {
      out.push(part.json);
    }
  }
  return out.length === 1 ? out[0] : out.length ? out : null;
};

// ---------- 启动真实 REA ----------
emit("tap_start", { childCmd, childArgs, logPath: LOG_PATH, mutate: MUTATE, node: process.version });

const child = spawn(childCmd, childArgs, {
  stdio: ["pipe", "pipe", "inherit"],
  env: process.env,
  windowsHide: true,
});

child.on("error", (e) => {
  emit("tap_error", { where: "spawn", error: String(e?.message ?? e) });
  process.exit(1);
});
child.on("exit", (code, signal) => {
  emit("child_exit", { code, signal });
  try { log.end(); } catch {}
});

// ---------- stdio 双向转发 ----------
// 用「按行切分 JSON」而不是 readline：MCP 走行分隔 JSON-RPC，但要容忍
// 半行到达，所以自己维护缓冲。
const makeSplitter = (onMessage) => {
  let buf = "";
  return (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, idx).replace(/\r$/, "");
      buf = buf.slice(idx + 1);
      if (line.trim() === "") continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        onMessage(null, line); // 非 JSON，原样透传
        continue;
      }
      onMessage(msg, line);
    }
  };
};

// dsh -> REA
const intoChild = makeSplitter((msg, raw) => {
  if (msg === null) {
    emit("c2s_rawl", { raw: raw.slice(0, 2000) });
    child.stdin.write(raw + "\n");
    return;
  }
  if (msg.method === "tools/call") {
    const { name, arguments: args } = msg.params ?? {};
    pending.set(msg.id, { name, args, at: Date.now() });
    emit("c2s_call", { rpcId: msg.id, tool: name, args });
    if (VERBOSE) process.stderr.write(`rea-tap → ${name}\n`);
  } else if (msg.method) {
    emit("c2s_req", { rpcId: msg.id, method: msg.method, params: msg.params });
  }
  child.stdin.write(raw + "\n");
});

// REA -> dsh
const fromChild = makeSplitter((msg, raw) => {
  if (msg === null) {
    emit("s2c_rawl", { raw: raw.slice(0, 2000) });
    process.stdout.write(raw + "\n");
    return;
  }
  if (msg.id !== undefined && pending.has(msg.id)) {
    const req = pending.get(msg.id);
    pending.delete(msg.id);
    const structured = extractStructured(msg);
    const prof = structured ? profileEvidence(structured) : null;
    emit("s2c_result", {
      rpcId: msg.id,
      tool: req.name,
      duration_ms: Date.now() - req.at,
      isError: msg.result?.isError === true || msg.error !== undefined,
      error: msg.error ?? undefined,
      evidenceCount: prof?.ids.length ?? 0,
      evidenceIds: prof?.ids.slice(0, 40) ?? [],
      authorities: prof?.authorities ?? {},
      confidences: prof?.confidences ?? {},
      unknowns: prof?.unknowns ?? 0,
      coverage: [...new Set(prof?.coverage ?? [])].slice(0, 20),
    });
  } else if (msg.method) {
    emit("s2c_req", { method: msg.method, params: msg.params });
  }

  let out = raw;
  if (MUTATE) out = mutateResponse(msg, raw) ?? raw;
  process.stdout.write(out + "\n");
});

/**
 * 改写钩子（REA_TAP_MUTATE=1 时才生效）。
 * 目前只做「观测即改写」的骨架，把可改点标出来，不默认启用。
 */
function mutateResponse(msg, raw) {
  const req = msg?.id !== undefined ? pending.get(msg.id) : undefined;
  if (!req) return null;
  emit("mutate_seen", { rpcId: msg.id, tool: req.name, note: "hook 已触发，未实施改写" });
  return null; // 返回 null = 不改
}

process.stdin.on("data", intoChild);
child.stdout.on("data", fromChild);

// 收尾：stdin 关闭时优雅结束子进程
process.stdin.on("end", () => {
  emit("tap_stdin_end", { pending: pending.size });
  try { child.stdin.end(); } catch {}
});

const shutdown = (sig) => {
  emit("tap_shutdown", { signal: sig, pending: pending.size });
  try { child.kill(); } catch {}
  try { log.end(); } catch {}
  process.exit(0);
};
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
