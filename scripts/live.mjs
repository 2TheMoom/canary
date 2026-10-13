// Live helper for Canary on Bradbury.
//   node scripts/live.mjs register <url> <phrase> <maxAgeDays> <window>
//   node scripts/live.mjs check <canaryId>
//   node scripts/live.mjs show <canaryId>
//   node scripts/live.mjs id <url> <phrase> <maxAgeDays> <window>
// Signs with a dedicated testnet wallet kept outside the repo.
import { readFileSync } from "fs";
import { createAccount, createClient } from "genlayer-js";
import { testnetBradbury } from "genlayer-js/chains";

const CONTRACT = process.env.CANARY || "0x80C94f43183b2342101bbd8ed4038184a33759D5";
const WALLETS = JSON.parse(readFileSync("C:/Users/olumi/.genlayer-test-wallets/wallets.json", "utf8"));
const client = createClient({ chain: testnetBradbury, account: createAccount(WALLETS["gl-test-1"].privateKey) });

const j = (x) => JSON.stringify(x, (k, v) => (typeof v === "bigint" ? v.toString() : v), 1);
const plain = (x) => (x instanceof Map ? Object.fromEntries([...x].map(([k, v]) => [k, plain(v)])) : Array.isArray(x) ? x.map(plain) : x);

async function read(functionName, args) {
  for (let i = 0; i < 6; i++) {
    try {
      return plain(await client.readContract({ address: CONTRACT, functionName, args }));
    } catch (e) {
      if (i === 5) throw e;
      await new Promise((r) => setTimeout(r, 8000));
    }
  }
}

async function write(functionName, args) {
  const hash = await client.writeContract({ address: CONTRACT, functionName, args });
  console.log(`  ${functionName} tx ${hash}`);
  for (let attempt = 1; ; attempt++) {
    try {
      const r = await client.waitForTransactionReceipt({ hash, retries: 200 });
      console.log(`  exec=${r.txExecutionResultName} result=${r.resultName}`);
      return { hash, r };
    } catch (e) {
      if (attempt >= 10) throw e;
      console.log("  (receipt poll failed, retrying)");
      await new Promise((r) => setTimeout(r, 15000));
    }
  }
}

const [cmd, ...a] = process.argv.slice(2);
if (cmd === "id") {
  console.log(await read("canary_id", [a[0], a[1], Number(a[2]), Number(a[3])]));
} else if (cmd === "register") {
  const id = await read("canary_id", [a[0], a[1], Number(a[2]), Number(a[3])]);
  await write("register", [a[0], a[1], Number(a[2]), Number(a[3])]);
  console.log("id:", id);
} else if (cmd === "check") {
  await write("check", [a[0]]);
  console.log(j(await read("get_canary", [a[0]])));
} else if (cmd === "show") {
  console.log(j(await read("get_canary", [a[0]])));
  console.log("history:", j(await read("get_history", [a[0]])));
  console.log("is_alive(1h):", await read("is_alive", [a[0], 3600]));
} else {
  console.error("unknown command");
  process.exit(1);
}
