#!/usr/bin/env node
/**
 * 冒烟测试：通过 rea-tap 发一次真实 MCP 握手 + tools/list，
 * 验证代理的透明性（转发无损）与观测能力（日志有成对记录）。
 *
 * 用法：node smoke.mjs
 */

import { spawn } from "node:child_process";
import { readFileSync, existsSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const LOG = `${HERE}/smoke-test.ndjson`;
if (existsSync(LOG)) rmSync(LOG);

if (!process.env.REA_CMD) {
  console.error("缺少环境变量 REA_CMD。");
  console.error('示例：REA_CMD="node /path/to/reverse-tool.mjs mcp" node smoke.mjs');
  process.exit(1);
}
const CMD = process.env.REA_CMD.split(/\s+/).filter(Boolean);
const NODE = process.execPath;

const tap = spawn(NODE, [`${HERE}/rea-tap.mjs`, "--", ...CMD], {
  stdio: ["pipe", "pipe", "pipe"],
  env: { ...process.env, REA_TAP_LOG: LOG, REA_TAP_VERBOSE: "1" },
});

let out = "";
tap.stdout.on("data", (d) => (out += d));
let err = "";
tap.stderr.on("data", (d) => (err += d));

const send = (obj) => tap.stdin.write(JSON.stringify(obj) + "\n");

const waitForResponse = (id, timeoutMs = 60000) =>
  new Promise((res, rej) => {
    const t = setTimeout(() => rej(new Error(`等待 id=${id} 超时\nstderr:\n${err.slice(-1500)}`)), timeoutMs);
    const check = () => {
      for (const line of out.split("\n")) {
        if (!line.trim()) continue;
        try {
          const m = JSON.parse(line);
          if (m.id === id) { clearTimeout(t); return res(m); }
        } catch {}
      }
      setTimeout(check, 200);
    };
    check();
  });

const main = async () => {
  console.log("1) 发送 initialize ...");
  send({
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "rea-tap-smoke", version: "1.0.0" },
    },
  });
  const init = await waitForResponse(1);
  const si = init.result?.serverInfo ?? {};
  console.log(`   ✅ 服务端: ${si.name ?? "?"} v${si.version ?? "?"}`);
  console.log(`   协议: ${init.result?.protocolVersion ?? "?"}`);

  send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });

  console.log("2) 请求 tools/list ...");
  send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  const list = await waitForResponse(2);
  const tools = list.result?.tools ?? [];
  console.log(`   ✅ 工具数: ${tools.length}`);

  // 挑几个有代表性的名字做样本
  const sample = tools.map((t) => t.name).filter((n) =>
    ["open_binary", "binary_overview", "analyze_function", "export_evidence_bundle",
     "record_unknown", "list_unknowns", "verify_reconstruction"].includes(n));
  console.log(`   样本命中: ${sample.join(", ") || "(无)"}`);
  console.log(`   前 8 个: ${tools.slice(0, 8).map((t) => t.name).join(", ")}`);

  console.log("3) 调用一个真实工具（list_documents，无目标也应安全返回）...");
  send({
    jsonrpc: "2.0", id: 3, method: "tools/call",
    params: { name: "list_documents", arguments: {} },
  });
  const call = await waitForResponse(3);
  const isErr = call.result?.isError === true;
  console.log(`   ${isErr ? "⚠" : "✅"} 返回 isError=${isErr}`);
  const txt = call.result?.content?.[0]?.text ?? "";
  console.log(`   返回摘要: ${txt.slice(0, 200).replace(/\n/g, " ")}`);

  // ---- 校验日志 ----
  console.log("\n4) 校验观测日志 ...");
  await new Promise((r) => setTimeout(r, 500));
  tap.kill();
  await new Promise((r) => setTimeout(r, 300));

  if (!existsSync(LOG)) throw new Error("日志文件未生成");
  const lines = readFileSync(LOG, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const kinds = {};
  for (const l of lines) kinds[l.kind] = (kinds[l.kind] ?? 0) + 1;

  console.log(`   日志行数: ${lines.length}`);
  console.log(`   事件分布: ${JSON.stringify(kinds)}`);

  const start = lines.find((l) => l.kind === "tap_start");
  const calls = lines.filter((l) => l.kind === "c2s_call");
  const results = lines.filter((l) => l.kind === "s2c_result");
  console.log(`   tap_start: ${start ? "✅" : "❌"}`);
  console.log(`   工具调用记录: ${calls.length} 条 (期望 1)`);
  console.log(`   调用结果记录: ${results.length} 条 (期望 1)`);
  if (calls[0]) console.log(`   捕获调用: ${calls[0].tool}`);
  if (results[0]) {
    console.log(`   捕获结果: tool=${results[0].tool} 耗时=${results[0].duration_ms}ms ` +
      `evidence=${results[0].evidenceCount} isError=${results[0].isError}`);
  }
  const initRec = lines.find((l) => l.kind === "c2s_req" && l.method === "initialize");
  console.log(`   initialize 记录: ${initRec ? "✅" : "❌"}`);

  const ok = start && calls.length === 1 && results.length === 1 && initRec;
  console.log(`\n${ok ? "✅ 冒烟测试通过：代理透明转发 + 观测完整" : "❌ 冒烟测试失败"}`);
  process.exit(ok ? 0 : 1);
};

main().catch((e) => {
  console.error("❌ 测试异常:", e.message);
  try { tap.kill(); } catch {}
  process.exit(1);
});
