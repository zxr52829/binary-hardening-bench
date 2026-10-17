// 单函数深挖：拉取指定地址的完整伪代码与引用面
//
// 用法：
//   REA_CMD="node /path/to/reverse-tool.mjs mcp" node look.mjs <binary> <address>
//
// 环境变量：
//   REA_CMD  逆向工具的 MCP 启动命令（必填，会被 shell 按空格切分）
//   REA_TAP  代理脚本路径（默认取本文件同目录的 rea-tap.mjs）
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const TAP = process.env.REA_TAP || join(HERE, "rea-tap.mjs");

// 先校验参数，再校验环境变量：本地调试时最容易漏的是地址，先报到点上。
const target = process.argv[2];
const procAddr = process.argv[3];

if (!target || !procAddr) {
  console.error("用法: REA_CMD=\"...\" node look.mjs <目标路径> <函数地址>");
  console.error("示例: node look.mjs ../lab/target-vm5.exe 0x140001480");
  process.exit(1);
}

if (!process.env.REA_CMD) {
  console.error("缺少环境变量 REA_CMD。");
  console.error('示例：REA_CMD="node /path/to/reverse-tool.mjs mcp" node look.mjs target.exe 0x140001000');
  process.exit(1);
}
const CMD = process.env.REA_CMD.split(/\s+/).filter(Boolean);

const child = spawn(process.execPath, [TAP, "--", ...CMD], {
  stdio: ["pipe", "pipe", "pipe"],
  env: { ...process.env, REA_TAP_LOG: "look.tmp.ndjson" },
});

let id = 0;
const waiters = new Map();
let buf = "";
child.stdout.on("data", (d) => {
  buf += d.toString("utf8");
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.id !== undefined && waiters.has(msg.id)) {
      waiters.get(msg.id)(msg);
      waiters.delete(msg.id);
    }
  }
});
child.stderr.on("data", () => {});

function call(method, params) {
  return new Promise((resolve, reject) => {
    const myId = ++id;
    waiters.set(myId, resolve);
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: myId, method, params }) + "\n");
    setTimeout(() => {
      if (waiters.has(myId)) {
        waiters.delete(myId);
        reject(new Error("timeout " + method));
      }
    }, 300000);
  });
}

function env(resp) {
  const t = resp.result?.content?.[0]?.text;
  if (!t) return null;
  const o = JSON.parse(t);
  return o.result ? o.result : o;
}

await call("initialize", {
  protocolVersion: "2024-11-05",
  capabilities: {},
  clientInfo: { name: "look", version: "1" },
});
child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");

await call("tools/call", { name: "open_binary", arguments: { path: resolve(target) } });
const r = await call("tools/call", { name: "analyze_function", arguments: { procedure: procAddr } });
const e = env(r)?.normalized_result;
if (!e) { console.log("RAW:", JSON.stringify(r).slice(0,2000)); process.exit(1); }
if (!e.procedure) { console.log("ENV KEYS:", Object.keys(e).join(",")); console.log("SAMPLE:", JSON.stringify(e).slice(0,1500)); process.exit(1); }

console.log("=== procedure ===");
console.log(e.procedure.signature);
console.log("body bytes:", e.procedure.body.total_bytes);
console.log("=== pseudocode ===");
console.log(e.pseudocode);
console.log("=== referenced_strings ===");
console.log(JSON.stringify(e.referenced_strings, null, 1));
console.log("=== callees ===");
console.log((e.callees || []).map((c) => c.value || c).join(", "));

child.kill();
process.exit(0);
