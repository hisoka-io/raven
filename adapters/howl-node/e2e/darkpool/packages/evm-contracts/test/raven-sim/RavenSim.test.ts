// Multi-agent simulation on a local anvil chain: five wallets with different strategies send real
// proofs to Howl's deployed pool, and every note each wallet holds, and every Merkle path it spends
// with, comes through a Raven Howl node following that chain. After every transaction each wallet is
// graded against an independent scan of the chain's own logs and against the pool's token balances.
//
// Run against a fresh anvil with `--network simAnvil`. Environment: SIM_RPC_URL (anvil), SIM_NODE_PORT,
// SIM_OUT_DIR (run log), HOWL_NODE_BIN (the Raven Howl node), RAVEN_SDK and RAVEN_WASM (the Raven client
// package's dist/index.js and its nodejs wasm); optional SIM_ROUNDS, SIM_SEED, SIM_PRESEED_START/HALF,
// SIM_BULK_TO (grow the pool to this many leaves at the end, then act once more) and
// SIM_PLANT_DROP_FEED_LEAF (a negative control: the wallets are served a feed with that row blanked, as a
// node that drops a feed leaf would serve it; the run must then report mismatches). SIM_PARAM_SET starts
// the node under that parameter set. SIM_SMOKE=1 is a short check: no mid-run restart, no reorganisation,
// and SIM_MIN_TX (default 100) sets the transaction floor.
import { expect } from "chai";
import { ethers } from "hardhat";
import type { ContractTransactionResponse } from "ethers";
import { spawn, type ChildProcess } from "node:child_process";
import {
  appendFileSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { loadavg } from "node:os";
import { join } from "node:path";
import {
  Fr,
  toFr,
  addressToFr,
  publicKey,
  newSeededTree,
  packParents,
} from "@hisoka/wallets";
import { proveDeposit, proveWithdraw, type ProofData } from "@hisoka/prover";
import { hashUniswapIntent, SwapType } from "@hisoka/adaptors";
import type { Point } from "@zk-kit/baby-jubjub";
import {
  deployDarkPoolFixture,
  makeDeposit,
  COMPLIANCE_PK,
  evenYEphemeral,
  mintSelfNote,
  userSpendScalar,
} from "../helpers/fixtures";
import { RavenAgent, type FoundNote, type RavenSource } from "./ravenAgent";
import type { DarkPool, MockERC20 } from "../../typechain-types";

const env = (k: string): string => {
  const v = process.env[k];
  if (v === undefined || v === "")
    throw new Error(`${k} is required (see the header of this file)`);
  return v;
};

const OUT = env("SIM_OUT_DIR");
const SEED = Number(process.env.SIM_SEED ?? "20261015");
const ROUNDS = Number(process.env.SIM_ROUNDS ?? "24");
// Notes of other pool users, deposited before the wallets start and again halfway, so the wallets'
// notes span full blocks, more than one shard, and paths that need the upper levels.
const PRESEED_START = Number(process.env.SIM_PRESEED_START ?? "0");
const PRESEED_HALF = Number(process.env.SIM_PRESEED_HALF ?? "0");
// Pool size for the scale phase. One real outsider proof is sent again and again: the pool inserts a
// repeated commitment like any other, so the node's load per leaf is what it is for distinct notes.
const BULK_TO = Number(process.env.SIM_BULK_TO ?? "0");
const PLANT_DROP_LEAF =
  process.env.SIM_PLANT_DROP_FEED_LEAF === undefined
    ? -1
    : Number(process.env.SIM_PLANT_DROP_FEED_LEAF);
const PARAM_SET = process.env.SIM_PARAM_SET ?? "";
const SMOKE = process.env.SIM_SMOKE === "1";
const MIN_TX = Number(process.env.SIM_MIN_TX ?? "100");
const UNIT = 10n ** 15n;
const LEAF_INSERTED = ethers.id("LeafInserted(uint256,bytes32,bytes32)");
// Howl's generated verifiers revert from assembly with these selectors (their Errors.sol names)
const VERIFIER_ERRORS: Record<string, string> = {
  "0xeb73e0bd": "ValueGeLimbMax",
  "0x607be13e": "ValueGeGroupOrder",
  "0x20a33589": "ValueGeFieldOrder",
  "0x9fc3a218": "SumcheckFailed",
  "0xa5d82e8a": "ShpleminiFailed",
  "0x59895a53": "ProofLengthWrongWithLogN",
  "0xfa066593": "PublicInputsLengthWrong",
  "0xf442f163": "ModexpFailed",
  "0xa2a2ac83": "ConsistencyCheckFailed",
  "0x835eb8f7": "GeminiChallengeInSubgroup",
};
const PROOF_REJECTED = new Set([
  "InvalidProof",
  ...Object.values(VERIFIER_ERRORS),
]);

// ---------------------------------------------------------------- deterministic choices
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = rng(SEED);
const randInt = (lo: number, hi: number) =>
  lo + Math.floor(rand() * (hi - lo + 1));
const pickOne = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)]!;
function shuffle<T>(xs: T[]): T[] {
  for (let i = xs.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [xs[i], xs[j]] = [xs[j]!, xs[i]!];
  }
  return xs;
}
function weighted<T extends string>(w: Record<T, number>): T {
  const entries = Object.entries(w) as [T, number][];
  const total = entries.reduce((s, [, x]) => s + x, 0);
  let r = rand() * total;
  for (const [k, x] of entries) if ((r -= x) <= 0) return k;
  return entries[entries.length - 1]![0];
}

// ---------------------------------------------------------------- run log
const jsonl = (file: string, row: unknown) =>
  appendFileSync(
    join(OUT, file),
    JSON.stringify(row, (_, v) => (typeof v === "bigint" ? v.toString() : v)) +
      "\n",
  );

interface RouteSample {
  agent: string;
  method: string;
  route: string;
  ms: number;
  up: number;
  down: number;
  status: number;
  // the parameter-set id in the request prefix and in the answer header (bytes 2..4, big endian)
  reqSet: number | null;
  ansSet: number | null;
}
const setId = (b: Uint8Array) => (b.length >= 4 ? (b[2]! << 8) | b[3]! : null);
const routeSamples: RouteSample[] = [];

function timedTransport(
  base: {
    get(p: string): Promise<any>;
    post(p: string, b: Uint8Array): Promise<any>;
  },
  agent: string,
) {
  const route = (p: string) => p.split("?")[0]!.replace(/\/\d+$/, "/:n");
  return {
    async get(path: string) {
      const t0 = performance.now();
      const ex = plantDroppedRow(route(path), await base.get(path));
      routeSamples.push({
        agent,
        method: "GET",
        route: route(path),
        ms: performance.now() - t0,
        up: 0,
        down: ex.body.length,
        status: ex.status,
        reqSet: null,
        ansSet: ex.status === 200 ? setId(new Uint8Array(ex.body)) : null,
      });
      return ex;
    },
    async post(path: string, body: Uint8Array) {
      const t0 = performance.now();
      const ex = await base.post(path, body);
      routeSamples.push({
        agent,
        method: "POST",
        route: route(path),
        ms: performance.now() - t0,
        up: body.length,
        down: ex.body.length,
        status: ex.status,
        reqSet: setId(body),
        ansSet: ex.status === 200 ? setId(new Uint8Array(ex.body)) : null,
      });
      return ex;
    },
  };
}

/**
 * The planted node: blank feed row PLANT_DROP_LEAF in every sync and prefixes answer. The feed is not
 * bound by the root, so the client takes the row as served, exactly as from a node that lost it.
 */
let plantHits = 0;
function plantDroppedRow(route: string, ex: any) {
  if (PLANT_DROP_LEAF < 0 || ex.status !== 200) return ex;
  if (route !== "/howl/v1/sync" && route !== "/howl/v1/prefixes") return ex;
  const body = new Uint8Array(ex.body);
  const view = new DataView(body.buffer);
  const base = Number(view.getBigUint64(56));
  const next = Number(view.getBigUint64(64));
  if (PLANT_DROP_LEAF < base || PLANT_DROP_LEAF >= next) return ex;
  const at = 72 + (PLANT_DROP_LEAF - base) * 6;
  body.fill(0, at, at + 6);
  plantHits += 1;
  return { ...ex, body };
}

const dirBytes = (dir: string): number =>
  readdirSync(dir, { withFileTypes: true }).reduce(
    (s, e) =>
      s +
      (e.isDirectory()
        ? dirBytes(join(dir, e.name))
        : statSync(join(dir, e.name)).size),
    0,
  );

// ---------------------------------------------------------------- the node
class HowlNode {
  proc: ChildProcess | null = null;
  readonly url: string;
  starts = 0;
  constructor(
    readonly bin: string,
    readonly rpc: string,
    readonly dataDir: string,
    readonly pool: string,
    readonly deploymentBlock: number,
    readonly port: number,
  ) {
    this.url = `http://127.0.0.1:${port}`;
  }
  start() {
    this.starts += 1;
    process.once("exit", () => this.proc?.kill("SIGKILL"));
    const args = [
      "--data-dir",
      this.dataDir,
      "--chain-id",
      "31337",
      "--pool",
      this.pool,
      "--deployment-block",
      String(this.deploymentBlock),
      "--listen",
      `127.0.0.1:${this.port}`,
      "--poll-ms",
      "100",
      ...(PARAM_SET === "" ? [] : ["--param-set", PARAM_SET]),
    ];
    this.proc = spawn(this.bin, args, {
      env: { ...process.env, HOWL_NODE_RPC_URL: this.rpc, RUST_LOG: "info" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const log = join(OUT, "node.log");
    this.proc.stdout!.on("data", (d) => appendFileSync(log, d));
    this.proc.stderr!.on("data", (d) => appendFileSync(log, d));
  }
  async stop() {
    if (this.proc && this.proc.exitCode === null) {
      const p = this.proc;
      p.kill("SIGINT");
      await new Promise((r) => p.once("exit", r));
    }
    this.proc = null;
  }
  async health(): Promise<{
    leaves: number;
    block: number;
    shards: number;
    sessions: number;
  } | null> {
    try {
      const r = await fetch(`${this.url}/howl/v1/health`);
      if (r.status !== 200) return null;
      const f = Object.fromEntries(
        (await r.text())
          .trim()
          .split(/\s+/)
          .slice(1)
          .map((kv) => kv.split("=")),
      );
      return {
        leaves: Number(f.leaves),
        block: Number(f.block),
        shards: Number(f.shards),
        sessions: Number(f.sessions),
      };
    } catch {
      return null;
    }
  }
  memory(): { rssKiB: number; hwmKiB: number } {
    const s = readFileSync(`/proc/${this.proc!.pid}/status`, "utf8");
    const kib = (k: string) =>
      Number(new RegExp(`${k}:\\s+(\\d+)`).exec(s)![1]);
    return { rssKiB: kib("VmRSS"), hwmKiB: kib("VmHWM") };
  }
}

// ---------------------------------------------------------------- the simulation
describe("Raven multi-agent simulation on Howl's contracts", function () {
  this.timeout(0);

  it("five wallets, 100+ transactions, every note and path through Raven, zero mismatches", async function () {
    rmSync(OUT, { recursive: true, force: true });
    mkdirSync(OUT, { recursive: true });

    const sdk = require(env("RAVEN_SDK"));
    const wasm = require(env("RAVEN_WASM"));

    const provider = ethers.provider;
    const signers = await ethers.getSigners();
    const deployBlock = await provider.getBlockNumber();
    const base = await deployDarkPoolFixture();
    const { darkPool, token } = base;
    const poolAddr = await darkPool.getAddress();

    // swap venue: Howl's adaptor over the mock router (1:1 output)
    const tokenOut = (await (
      await ethers.getContractFactory("MockERC20")
    ).deploy("Out", "OUT", 18)) as unknown as MockERC20;
    const router = await (
      await ethers.getContractFactory("MockSwapRouter")
    ).deploy();
    await (
      await tokenOut.mint(
        await router.getAddress(),
        ethers.parseEther("100000"),
      )
    ).wait();
    await (
      await token.mint(await router.getAddress(), ethers.parseEther("100000"))
    ).wait();
    const poseidon2 = await (
      await ethers.getContractFactory("Poseidon2")
    ).deploy();
    const adaptor = await (
      await ethers.getContractFactory("UniswapAdaptor", {
        libraries: { Poseidon2: await poseidon2.getAddress() },
      })
    ).deploy(poolAddr, await router.getAddress());
    const assetA = await token.getAddress();
    const assetB = await tokenOut.getAddress();
    const ASSETS = [assetA, assetB];

    const roster: [string, string, number][] = [
      ["alice", "greedy", 1],
      ["bob", "cheater", 2],
      ["charlie", "donor", 3],
      ["david", "philanthropist", 7],
      ["ellie", "trader", 8],
    ];
    for (const [, , i] of roster) {
      if ((await token.balanceOf(signers[i]!.address)) === 0n)
        await (
          await token.mint(signers[i]!.address, ethers.parseEther("10000"))
        ).wait();
    }

    // Raven: the node binary following this chain from before the pool's deployment
    const node = new HowlNode(
      env("HOWL_NODE_BIN"),
      env("SIM_RPC_URL"),
      join(OUT, "node-data"),
      poolAddr,
      deployBlock,
      Number(env("SIM_NODE_PORT")),
    );
    if ((await node.health()) !== null)
      throw new Error(`port ${node.port} already serves a node`);
    node.start();
    const nodeT0 = Date.now();
    while ((await node.health()) === null) {
      if (Date.now() - nodeT0 > 60_000) throw new Error("node did not start");
      await new Promise((r) => setTimeout(r, 100));
    }

    // chain truth for every leaf and root: LeafInserted(leafIndex, leaf, newRoot), read again whenever
    // the head block's hash changes, so a reorganisation is never graded against orphaned logs
    let rootAfter = new Map<number, string>();
    let leafAt = new Map<number, string>();
    let scannedAt = "";
    const chainLogs = async () => {
      const head = (await provider.getBlock("latest"))!;
      if (head.hash !== scannedAt) {
        const logs = await provider.getLogs({
          address: poolAddr,
          topics: [LEAF_INSERTED],
          fromBlock: 0,
          toBlock: head.number,
        });
        rootAfter = new Map();
        leafAt = new Map();
        for (const l of logs) {
          const i = Number(BigInt(l.topics[1]!));
          leafAt.set(i, "0x" + l.data.slice(2, 66));
          rootAfter.set(i + 1, "0x" + l.data.slice(66, 130));
        }
        scannedAt = head.hash!;
      }
    };
    const chainRootAt = async (count: number) => {
      await chainLogs();
      return rootAfter.get(count);
    };

    const agents: RavenAgent[] = [];
    const sources: RavenSource[] = [];
    for (const [name, strategy, i] of roster) {
      const transport = timedTransport(
        sdk.fetchTransport(node.url, { timeoutMs: 120_000 }),
        name,
      );
      const source = new sdk.RavenHowlSource({
        transport,
        wasm,
        field: {
          fromBytes: (b: Uint8Array) => Fr.fromBuffer(Buffer.from(b)),
          toBytes: (f: Fr) => new Uint8Array(f.toBuffer()),
        },
        // one wallet carries its key in every request; the others hold a session
        keyMode: name === "ellie" ? "inline" : "session",
      }) as RavenSource;
      sources.push(source);
      agents.push(
        await RavenAgent.create(
          name,
          strategy,
          signers[i]! as any,
          darkPool,
          token,
          source,
          chainRootAt,
        ),
      );
    }
    const byName = new Map(agents.map((a) => [a.name, a]));

    // ------------------------------------------------------------ public ledger
    const expectedPublic = new Map<string, Map<string, bigint>>();
    for (const a of agents) {
      const m = new Map<string, bigint>();
      for (const asset of ASSETS)
        m.set(
          asset,
          await (asset === assetA ? token : tokenOut).balanceOf(a.address),
        );
      expectedPublic.set(a.address, m);
    }
    const movePublic = (who: string, asset: string, delta: bigint) => {
      const m = expectedPublic.get(who);
      if (m) m.set(asset, m.get(asset)! + delta);
    };
    const erc = (asset: string) => (asset === assetA ? token : tokenOut);
    // value deposited by a pool user outside the simulation (the reorg phase)
    let outsideValue = 0n;

    // ------------------------------------------------------------ bookkeeping
    let step = 0;
    let txOk = 0;
    let txRejected = 0;
    let mismatches = 0;
    const kinds: Record<string, number> = {};
    const rejectedKinds: Record<string, number> = {};
    const followLagMs: number[] = [];
    const discoveryMs: number[] = [];
    const memSamples: {
      step: number;
      start: number;
      rssKiB: number;
      hwmKiB: number;
      leaves: number;
      sessions: number;
    }[] = [];
    // the scale phase: node memory and disk at each 1,024 leaves, the node caught up and idle
    const scaleSamples: {
      leaves: number;
      shards: number;
      sessions: number;
      rssKiB: number;
      hwmKiB: number;
      dataDirBytes: number;
      followLagMs: number;
    }[] = [];
    // other pool users' transactions: never in txOk or kinds, which count the five wallets only
    let outsiderTx = 0;
    const outsiderKinds = { preseed: 0, reorgDeposit: 0, bulkReplays: 0 };
    const lastProofs = new Map<
      string,
      {
        kind: string;
        call: (o?: {
          gasLimit: number;
        }) => Promise<ContractTransactionResponse>;
        staticCall: () => Promise<unknown>;
      }
    >();
    let witnessCursor = new Map<string, number>(agents.map((a) => [a.name, 0]));

    const nodeRoot = async (count: number): Promise<string | null> => {
      const r = await fetch(`${node.url}/howl/v1/prefixes?since=${count}`);
      if (r.status !== 200) return null;
      const body = new Uint8Array(await r.arrayBuffer());
      return ethers.hexlify(body.subarray(24, 56));
    };
    const waitCaughtUp = async (): Promise<number> => {
      const t0 = performance.now();
      const want = Number(await darkPool.getNextLeafIndex());
      const head = await provider.getBlockNumber();
      const root = await chainRootAt(want);
      for (;;) {
        const h = await node.health();
        if (h !== null && h.leaves === want && h.block >= head) {
          const served = await nodeRoot(want);
          if (
            served !== null &&
            root !== undefined &&
            BigInt(served) === BigInt(root)
          )
            return performance.now() - t0;
        }
        if (performance.now() - t0 > 120_000)
          throw new Error(
            `node stuck: ${JSON.stringify(h)} want ${want} @ ${head}`,
          );
        await new Promise((r) => setTimeout(r, 20));
      }
    };

    const fmt = (n: FoundNote) =>
      `${n.leafIndex}:${n.commitment}:${n.value}:${n.asset}:${n.spent ? "S" : "U"}:${n.incoming ? "in" : "self"}`;

    /** Grade every wallet after a step: Raven's notes against the chain's own logs and balances. */
    const verify = async (label: string, extra: Record<string, unknown>) => {
      const lag = await waitCaughtUp();
      followLagMs.push(lag);
      const perAgent: Record<string, unknown> = {};
      for (const a of agents) {
        const t0 = performance.now();
        const d = await a.discover();
        const ms = performance.now() - t0;
        discoveryMs.push(ms);
        const raven = a.found();
        const oracle = await a.oracle();
        const r = raven.map(fmt);
        const o = oracle.map(fmt);
        const missing = o.filter((x) => !r.includes(x));
        const extraNotes = r.filter((x) => !o.includes(x));
        if (missing.length + extraNotes.length > 0) {
          mismatches += missing.length + extraNotes.length;
          jsonl("mismatches.jsonl", {
            step,
            label,
            agent: a.name,
            missing,
            extra: extraNotes,
          });
        }
        // every Raven-found note's commitment is the chain's leaf at that index
        await chainLogs();
        for (const n of raven) {
          if (
            BigInt(leafAt.get(n.leafIndex) ?? "0x0") !== BigInt(n.commitment)
          ) {
            mismatches += 1;
            jsonl("mismatches.jsonl", {
              step,
              label,
              agent: a.name,
              leafNotOnChain: n.leafIndex,
            });
          }
        }
        const wc = witnessCursor.get(a.name)!;
        const newWitness = a.witnesses.slice(wc);
        witnessCursor.set(a.name, a.witnesses.length);
        for (const w of newWitness) {
          if (!w.knownRoot || !w.chainRootAtCount) {
            mismatches += 1;
            jsonl("mismatches.jsonl", {
              step,
              label,
              agent: a.name,
              witness: w,
            });
          }
        }
        perAgent[a.name] = {
          balances: Object.fromEntries(
            ASSETS.map((x) => [x === assetA ? "A" : "B", a.balance(x)]),
          ),
          notes: raven.length,
          unspent: raven.filter((n) => !n.spent).length,
          oracleNotes: oracle.length,
          rejectedRows: d.rejected,
          discoveryMs: Math.round(ms),
          witnesses: newWitness,
        };
      }
      // the pool holds exactly the wallets' unspent notes plus unclaimed public memos
      const memoLogs = await darkPool.queryFilter(
        darkPool.filters.NewPublicMemo(),
        0,
      );
      const spentMemo = new Set(
        (await darkPool.queryFilter(darkPool.filters.PublicMemoSpent(), 0)).map(
          (l) => l.args.memoId,
        ),
      );
      const pool: Record<string, unknown> = {};
      for (const asset of ASSETS) {
        const notes =
          agents.reduce((s, a) => s + a.balance(asset), 0n) +
          (asset === assetA ? outsideValue : 0n);
        const memos = memoLogs
          .filter(
            (l) =>
              !spentMemo.has(l.args.memoId) &&
              ethers.getAddress(l.args.asset) === asset,
          )
          .reduce((s, l) => s + l.args.value, 0n);
        const held = await erc(asset).balanceOf(poolAddr);
        if (notes + memos !== held) {
          mismatches += 1;
          jsonl("mismatches.jsonl", { step, label, asset, notes, memos, held });
        }
        pool[asset === assetA ? "A" : "B"] = { held, notes, memos };
        for (const a of agents) {
          const want = expectedPublic.get(a.address)!.get(asset)!;
          const got = await erc(asset).balanceOf(a.address);
          if (want !== got) {
            mismatches += 1;
            jsonl("mismatches.jsonl", {
              step,
              label,
              agent: a.name,
              asset,
              publicWant: want,
              publicGot: got,
            });
          }
        }
      }
      const mem = node.memory();
      const h = (await node.health())!;
      memSamples.push({
        step,
        start: node.starts,
        ...mem,
        leaves: h.leaves,
        sessions: h.sessions,
      });
      jsonl("steps.jsonl", {
        step,
        label,
        ...extra,
        leaves: h.leaves,
        block: h.block,
        sessions: h.sessions,
        followLagMs: Math.round(lag),
        load1: +loadavg()[0]!.toFixed(2),
        node: mem,
        pool,
        agents: perAgent,
        mismatchesSoFar: mismatches,
      });
    };

    /** One real transaction by `agent`. */
    const tx = async (
      agent: RavenAgent,
      kind: string,
      detail: Record<string, unknown>,
      send: (o?: { gasLimit: number }) => Promise<ContractTransactionResponse>,
      staticCall?: () => Promise<unknown>,
    ) => {
      step += 1;
      const t0 = performance.now();
      const resp = await send();
      const receipt = (await resp.wait())!;
      const ms = performance.now() - t0;
      txOk += 1;
      kinds[kind] = (kinds[kind] ?? 0) + 1;
      if (staticCall)
        lastProofs.set(agent.name, { kind, call: send, staticCall });
      const row = {
        step,
        ok: true,
        agent: agent.name,
        strategy: agent.strategy,
        kind,
        ...detail,
        tx: receipt.hash,
        blockNumber: receipt.blockNumber,
        gasUsed: receipt.gasUsed,
        sendMs: Math.round(ms),
      };
      jsonl("transactions.jsonl", row);
      await verify(`${agent.name} ${kind}`, {
        tx: receipt.hash,
        kind,
        agent: agent.name,
      });
    };

    /** A cheat: the pool must refuse it, on chain, with the named error, and nothing may change. */
    const cheat = async (
      agent: RavenAgent,
      kind: string,
      expected: string,
      call: (overrides: {
        gasLimit: number;
      }) => Promise<ContractTransactionResponse>,
      staticCall: () => Promise<unknown>,
    ) => {
      step += 1;
      const leavesBefore = await darkPool.getNextLeafIndex();
      let reason = "none";
      try {
        await staticCall();
        reason = "ACCEPTED";
      } catch (e: any) {
        const data = e?.data ?? e?.error?.data ?? e?.info?.error?.data;
        const verifierError =
          typeof data === "string"
            ? VERIFIER_ERRORS[data.slice(0, 10).toLowerCase()]
            : undefined;
        if (verifierError !== undefined) reason = verifierError;
        else
          try {
            reason = darkPool.interface.parseError(data)?.name ?? "unknown";
          } catch {
            try {
              reason = adaptor.interface.parseError(data)?.name ?? "unknown";
            } catch {
              reason = e?.shortMessage ?? String(e);
            }
          }
      }
      // and mined: the reverted transaction is on chain and leaves no note behind
      let status = -1;
      let hash = "";
      try {
        const resp = await call({ gasLimit: 12_000_000 });
        hash = resp.hash;
        const r = await provider.getTransactionReceipt(resp.hash);
        status = r ? Number(r.status) : -1;
        if (status === -1) {
          const rr = await provider.waitForTransaction(resp.hash);
          status = Number(rr!.status);
        }
      } catch (e: any) {
        status = e?.receipt ? Number(e.receipt.status) : 0;
        hash = e?.receipt?.hash ?? hash;
      }
      const leavesAfter = await darkPool.getNextLeafIndex();
      const matches =
        expected === "ProofRejected"
          ? PROOF_REJECTED.has(reason)
          : reason === expected;
      const ok = matches && status === 0 && leavesAfter === leavesBefore;
      if (!ok) mismatches += 1;
      txRejected += 1;
      rejectedKinds[kind] = (rejectedKinds[kind] ?? 0) + 1;
      jsonl("transactions.jsonl", {
        step,
        ok: false,
        agent: agent.name,
        strategy: agent.strategy,
        kind,
        expected,
        reason,
        minedStatus: status,
        tx: hash,
        asExpected: ok,
      });
      await verify(`${agent.name} cheat ${kind}`, {
        cheat: kind,
        reason,
        asExpected: ok,
      });
    };

    const amount = (lo: number, hi: number) => BigInt(randInt(lo, hi)) * UNIT;

    /** Other users' deposits: real proofs under tags no simulated wallet derives. */
    const outsider = signers[4]!;
    const preseed = async (count: number, label: string) => {
      if (count === 0) return;
      const t = Date.now();
      await (
        await token.connect(outsider).approve(poolAddr, ethers.MaxUint256)
      ).wait();
      const spend = await userSpendScalar(outsider.address);
      for (let i = 0; i < count; i++) {
        const eph = evenYEphemeral(
          BigInt(ethers.hexlify(ethers.randomBytes(16))),
        );
        const built = await mintSelfNote(eph, UNIT, spend, addressToFr(assetA));
        const proof = await proveDeposit({
          compliancePk: COMPLIANCE_PK,
          note: built.note,
          eph,
        });
        await (
          await darkPool
            .connect(outsider)
            .deposit(proof.proof, proof.publicInputs)
        ).wait();
        outsideValue += UNIT;
      }
      jsonl("transactions.jsonl", {
        step,
        ok: true,
        agent: "outsider",
        kind: "preseed deposits",
        count,
        seconds: Math.round((Date.now() - t) / 1000),
      });
      outsiderTx += count;
      outsiderKinds.preseed += count;
      await verify(`${label}: ${count} deposits by other users`, {
        preseed: count,
      });
    };

    /** Grow the pool to `target` leaves with one real outsider proof sent again and again. */
    const bulk = async (target: number) => {
      const t = Date.now();
      let leaves = Number(await darkPool.getNextLeafIndex());
      const count = target - leaves;
      if (count <= 0) return;
      const spend = await userSpendScalar(outsider.address);
      const eph = evenYEphemeral(
        BigInt(ethers.hexlify(ethers.randomBytes(16))),
      );
      const built = await mintSelfNote(eph, UNIT, spend, addressToFr(assetA));
      const proof = await proveDeposit({
        compliancePk: COMPLIANCE_PK,
        note: built.note,
        eph,
      });
      await (await token.mint(outsider.address, BigInt(count) * UNIT)).wait();
      await (
        await token.connect(outsider).approve(poolAddr, ethers.MaxUint256)
      ).wait();
      const pool = darkPool.connect(outsider);
      // the tree insert costs more as the tree deepens, so an estimate taken at a small pool runs out
      const gasLimit = 3_000_000;
      let nonce = await provider.getTransactionCount(
        outsider.address,
        "pending",
      );
      const sample = async () => {
        const lag = await waitCaughtUp();
        const h = (await node.health())!;
        scaleSamples.push({
          leaves: h.leaves,
          shards: h.shards,
          sessions: h.sessions,
          ...node.memory(),
          dataDirBytes: dirBytes(node.dataDir),
          followLagMs: Math.round(lag),
        });
      };
      await sample();
      let mark = (Math.floor(leaves / 1024) + 1) * 1024;
      // 128 deposits per block: anvil holds state per block, and one block per deposit grew it past
      // 5 GiB by 36,000 leaves
      await provider.send("evm_setAutomine", [false]);
      while (leaves < target) {
        const n = Math.min(128, target - leaves, mark - leaves);
        const sent: ContractTransactionResponse[] = [];
        for (let i = 0; i < n; i++)
          sent.push(
            await pool.deposit(proof.proof, proof.publicInputs, {
              nonce: nonce++,
              gasLimit,
            }),
          );
        await provider.send("evm_mine", []);
        for (const r of sent)
          if ((await r.wait())!.status !== 1)
            throw new Error(`bulk deposit ${r.hash} reverted`);
        leaves += n;
        outsideValue += BigInt(n) * UNIT;
        outsiderTx += n;
        outsiderKinds.bulkReplays += n;
        if (leaves === mark || leaves === target) {
          await sample();
          mark += 1024;
        }
      }
      await provider.send("evm_setAutomine", [true]);
      jsonl("transactions.jsonl", {
        step,
        ok: true,
        agent: "outsider",
        kind: "bulk deposits (one proof, sent again)",
        count,
        seconds: Math.round((Date.now() - t) / 1000),
      });
      await verify(`scale: the pool grown to ${target} leaves`, {
        bulk: count,
      });
    };

    // ------------------------------------------------------------ actions
    const deposit = async (
      a: RavenAgent,
      asset = assetA,
      value = amount(500, 5000),
    ) => {
      const proof = await a.proveDeposit(value, asset);
      await (
        await erc(asset).connect(a.signer).approve(poolAddr, value)
      ).wait();
      movePublic(a.address, asset, -value);
      await tx(a, "deposit", { asset, value }, () =>
        darkPool.connect(a.signer).deposit(proof.proof, proof.publicInputs),
      );
    };
    const withdraw = async (a: RavenAgent, asset: string, to: RavenAgent) => {
      const n = a.pick(asset, 2n * UNIT);
      const value = (n.note.value * BigInt(randInt(10, 90))) / 100n;
      const proof = await a.proveWithdraw(n, value, to.address);
      movePublic(to.address, asset, value);
      await tx(
        a,
        "withdraw",
        { asset, value, from: n.leafIndex, to: to.name },
        (o) =>
          darkPool
            .connect(a.signer)
            .withdraw(proof.proof, proof.publicInputs, o ?? {}),
        () =>
          darkPool
            .connect(a.signer)
            .withdraw.staticCall(proof.proof, proof.publicInputs),
      );
      return proof;
    };
    const addressBook = new Map<string, { inPub: Point<bigint> }[]>();
    const transfer = async (a: RavenAgent, asset: string, to: RavenAgent) => {
      const n = a.pick(asset, 2n * UNIT);
      const value = (n.note.value * BigInt(randInt(10, 90))) / 100n;
      // the recipient hands out a fresh address, or the sender reuses one it was given before
      const book = addressBook.get(`${a.name}->${to.name}`) ?? [];
      const reuse = book.length > 0 && rand() < 0.4;
      const addr = reuse ? pickOne(book) : await to.receiveAddress();
      if (!reuse) addressBook.set(`${a.name}->${to.name}`, [...book, addr]);
      const proof = await a.proveTransfer(n, value, addr.inPub);
      await tx(
        a,
        "transfer",
        { asset, value, from: n.leafIndex, to: to.name, reusedAddress: reuse },
        (o) =>
          darkPool
            .connect(a.signer)
            .privateTransfer(proof.proof, proof.publicInputs, o ?? {}),
        () =>
          darkPool
            .connect(a.signer)
            .privateTransfer.staticCall(proof.proof, proof.publicInputs),
      );
    };
    const split = async (a: RavenAgent, asset: string) => {
      const n = a.pick(asset, 2n * UNIT);
      const first = (n.note.value * BigInt(randInt(20, 80))) / 100n;
      const proof = await a.proveSplit(n, first);
      await tx(
        a,
        "split",
        {
          asset,
          from: n.leafIndex,
          value1: first,
          value2: n.note.value - first,
        },
        (o) =>
          darkPool
            .connect(a.signer)
            .split(proof.proof, proof.publicInputs, o ?? {}),
        () =>
          darkPool
            .connect(a.signer)
            .split.staticCall(proof.proof, proof.publicInputs),
      );
    };
    const joinNotes = async (a: RavenAgent, asset: string) => {
      const u = a.unspent(asset);
      const [x, y] = shuffle([...u])
        .slice(0, 2)
        .sort((p, q) => p.leafIndex - q.leafIndex);
      const proof = await a.proveJoin(x!, y!);
      await tx(
        a,
        "join",
        { asset, from: [x!.leafIndex, y!.leafIndex] },
        (o) =>
          darkPool
            .connect(a.signer)
            .join(proof.proof, proof.publicInputs, o ?? {}),
        () =>
          darkPool
            .connect(a.signer)
            .join.staticCall(proof.proof, proof.publicInputs),
      );
    };
    const swap = async (a: RavenAgent, assetIn: string) => {
      const assetOut = assetIn === assetA ? assetB : assetA;
      const n = a.pick(assetIn, 2n * UNIT);
      const amountIn = (n.note.value * BigInt(randInt(20, 70))) / 100n;
      const owner = await a.publicAddress();
      const salt = BigInt(ethers.hexlify(ethers.randomBytes(16)));
      const deadline =
        BigInt((await provider.getBlock("latest"))!.timestamp) + 600n;
      const intentHash = await hashUniswapIntent(
        {
          type: SwapType.ExactInputSingle,
          assetIn,
          assetOut,
          fee: 3000,
          recipient: { ownerX: owner[0], ownerY: owner[1] },
          amountOutMin: amountIn,
          salt,
        },
        deadline,
      );
      const proof = await a.proveWithdraw(
        n,
        amountIn,
        await adaptor.getAddress(),
        intentHash,
      );
      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
        [
          "tuple(address assetIn,address assetOut,uint24 fee,tuple(uint256 ownerX,uint256 ownerY) recipient,uint256 amountOutMin,uint256 salt)",
        ],
        [[assetIn, assetOut, 3000, [owner[0], owner[1]], amountIn, salt]],
      );
      await tx(
        a,
        "swap",
        { assetIn, assetOut, amountIn, from: n.leafIndex },
        () =>
          adaptor
            .connect(a.signer)
            .executeSwap(proof.proof, proof.publicInputs, 0, encoded, deadline),
      );
    };
    const publicTransfer = async (a: RavenAgent, to: RavenAgent) => {
      const value = amount(100, 1000);
      const owner = await to.publicAddress();
      const salt = BigInt(ethers.hexlify(ethers.randomBytes(16)));
      await (await token.connect(a.signer).approve(poolAddr, value)).wait();
      movePublic(a.address, assetA, -value);
      await tx(a, "publicTransfer", { value, to: to.name }, () =>
        darkPool
          .connect(a.signer)
          .publicTransfer(owner[0], owner[1], assetA, value, 0, salt),
      );
    };
    const claimAll = async (a: RavenAgent) => {
      const memos = (await a.publicMemos()).filter(
        (m) => m.claimable && !m.spent,
      );
      for (const m of memos) {
        const proof = await a.proveClaim(m);
        await tx(
          a,
          "publicClaim",
          { asset: m.asset, value: m.value, memo: m.memoId.toString() },
          (o) =>
            darkPool
              .connect(a.signer)
              .publicClaim(proof.proof, proof.publicInputs, o ?? {}),
          () =>
            darkPool
              .connect(a.signer)
              .publicClaim.staticCall(proof.proof, proof.publicInputs),
        );
      }
      return memos.length;
    };

    // ------------------------------------------------------------ the cheater's repertoire
    const cheats = [
      "replayOwn",
      "doubleSpend",
      "phantomNote",
      "tamperValue",
      "tamperRecipient",
      "replayOthersClaim",
    ] as const;
    let cheatTurn = 0;
    const doCheat = async (bob: RavenAgent): Promise<boolean> => {
      const which = cheats[cheatTurn++ % cheats.length]!;
      if (which === "replayOwn") {
        const last = lastProofs.get(bob.name);
        if (!last) return false;
        const expected =
          last.kind === "publicClaim" ? "MemoSpent" : "NullifierAlreadySpent";
        await cheat(
          bob,
          `replay ${last.kind}`,
          expected,
          (o) => last.call(o),
          last.staticCall,
        );
        return true;
      }
      if (which === "doubleSpend") {
        const spent = bob.spentNotes().filter((n) => n.asset === assetA);
        if (spent.length === 0) return false;
        const n = pickOne(spent);
        const proof = await bob.proveWithdraw(
          n,
          n.note.value / 2n,
          bob.address,
        );
        await cheat(
          bob,
          "double spend",
          "NullifierAlreadySpent",
          (o) =>
            darkPool
              .connect(bob.signer)
              .withdraw(proof.proof, proof.publicInputs, o),
          () =>
            darkPool
              .connect(bob.signer)
              .withdraw.staticCall(proof.proof, proof.publicInputs),
        );
        return true;
      }
      if (which === "phantomNote") {
        // a note that was never deposited, proven against a tree only bob has
        const tree = await newSeededTree(31337n);
        for (let i = 1; i < Number(await darkPool.getNextLeafIndex()); i++)
          await tree.insert(new Fr(BigInt(i) * 7919n));
        const spend = await userSpendScalar(bob.address);
        const eph = evenYEphemeral(
          BigInt(ethers.hexlify(ethers.randomBytes(8))),
        );
        const fake = await mintSelfNote(
          eph,
          2n * 10n ** 21n,
          spend,
          addressToFr(assetA),
        );
        await tree.insert(fake.commitment);
        const index = tree.nextLeafIndex - 1;
        const changeEph = evenYEphemeral(
          BigInt(ethers.hexlify(ethers.randomBytes(8))),
        );
        const change = await mintSelfNote(
          changeEph,
          10n ** 21n,
          spend,
          addressToFr(assetA),
          packParents([{ leafIndex: index }, { leafIndex: 0 }]),
        );
        const proof = await proveWithdraw({
          withdrawValue: toFr(10n ** 21n),
          recipient: addressToFr(bob.address),
          intentHash: toFr(0n),
          compliancePk: COMPLIANCE_PK,
          oldNote: fake.note,
          spendScalar: spend,
          oldNoteIndex: index,
          oldNotePath: tree.getMerklePath(index),
          changeNote: change.note,
          changeEph,
        });
        await cheat(
          bob,
          "phantom note withdraw",
          "InvalidRoot",
          (o) =>
            darkPool
              .connect(bob.signer)
              .withdraw(proof.proof, proof.publicInputs, o),
          () =>
            darkPool
              .connect(bob.signer)
              .withdraw.staticCall(proof.proof, proof.publicInputs),
        );
        return true;
      }
      if (which === "tamperValue" || which === "tamperRecipient") {
        const u = bob.unspent(assetA).filter((n) => n.note.value >= 4n * UNIT);
        if (u.length === 0) return false;
        const n = u[0]!;
        const proof: ProofData = await bob.proveWithdraw(
          n,
          n.note.value / 4n,
          bob.address,
        );
        const pi = [...proof.publicInputs];
        if (which === "tamperValue")
          pi[0] = ethers.toBeHex(BigInt(pi[0]!) * 4n, 32);
        else pi[1] = ethers.zeroPadValue(byName.get("alice")!.address, 32);
        await cheat(
          bob,
          which === "tamperValue"
            ? "withdraw with inflated value"
            : "withdraw redirected to another recipient",
          "ProofRejected",
          (o) => darkPool.connect(bob.signer).withdraw(proof.proof, pi, o),
          () =>
            darkPool.connect(bob.signer).withdraw.staticCall(proof.proof, pi),
        );
        return true;
      }
      // replay another wallet's public claim
      const theirs = [...lastProofs.entries()].find(
        ([who, p]) => who !== bob.name && p.kind === "publicClaim",
      );
      if (!theirs) return false;
      await cheat(
        bob,
        "replay another wallet's claim",
        "MemoSpent",
        (o) => theirs[1].call(o),
        theirs[1].staticCall,
      );
      return true;
    };

    // ------------------------------------------------------------ strategies
    const others = (a: RavenAgent) => agents.filter((x) => x !== a);
    const can = (a: RavenAgent, asset: string, n = 1) =>
      a.unspent(asset).filter((x) => x.note.value >= 2n * UNIT).length >= n;

    const act = async (a: RavenAgent) => {
      const hasA = can(a, assetA);
      const hasB = can(a, assetB);
      let choice: string;
      switch (a.strategy) {
        case "greedy": // hoards: deposits, consolidates, cashes out to itself, trades
          choice = weighted({
            deposit: hasA ? 2 : 10,
            join: a.unspent(assetA).length >= 2 ? 4 : 0,
            withdrawSelf: hasA ? 2 : 0,
            split: hasA ? 1 : 0,
            swap: hasA ? 1 : 0,
            claim: 1,
            joinB: a.unspent(assetB).length >= 2 ? 2 : 0,
          });
          break;
        case "cheater": // legitimate business, and an attempt to cheat on most turns
          if (rand() < 0.6 && (await doCheat(a))) return;
          choice = weighted({
            deposit: hasA ? 1 : 10,
            transfer: hasA ? 3 : 0,
            split: hasA ? 2 : 0,
            withdrawSelf: hasA ? 1 : 0,
            claim: 1,
          });
          break;
        case "donor": // gives privately to the others
          choice = weighted({
            deposit: hasA ? 1 : 10,
            transfer: hasA ? 6 : 0,
            split: hasA ? 2 : 0,
            publicTransfer: 1,
            claim: 1,
          });
          break;
        case "philanthropist": // gives to everyone, in private and in public
          choice = weighted({
            deposit: hasA ? 1 : 8,
            transfer: hasA ? 4 : 0,
            withdrawOther: hasA ? 3 : 0,
            publicTransfer: 2,
            claim: 1,
          });
          break;
        default: // trader: swaps both ways, claims the outputs, rearranges notes
          choice = weighted({
            deposit: hasA ? 1 : 8,
            swap: hasA ? 4 : 0,
            swapBack: hasB ? 3 : 0,
            claim: 4,
            split: hasA ? 1 : 0,
            join: a.unspent(assetA).length >= 2 ? 1 : 0,
            transferB: hasB ? 1 : 0,
          });
      }
      switch (choice) {
        case "deposit":
          return deposit(a);
        case "join":
          return joinNotes(a, assetA);
        case "joinB":
          return joinNotes(a, assetB);
        case "split":
          return split(a, assetA);
        case "withdrawSelf":
          return void (await withdraw(a, assetA, a));
        case "withdrawOther":
          return void (await withdraw(a, assetA, pickOne(others(a))));
        case "transfer":
          return transfer(a, assetA, pickOne(others(a)));
        case "transferB":
          return transfer(a, assetB, pickOne(others(a)));
        case "swap":
          return swap(a, assetA);
        case "swapBack":
          return swap(a, assetB);
        case "publicTransfer":
          return publicTransfer(a, pickOne(others(a)));
        case "claim":
          if ((await claimAll(a)) === 0) return deposit(a);
          return;
      }
    };

    // ------------------------------------------------------------ run
    const t0 = Date.now();
    try {
      await verify("start", {});
      await preseed(PRESEED_START, "before the wallets");
      // everyone starts with a deposit
      for (const a of agents) await deposit(a);

      let restarted = false;
      for (let round = 1; round <= ROUNDS; round++) {
        for (const a of shuffle([...agents])) {
          try {
            await act(a);
          } catch (e: any) {
            jsonl("errors.jsonl", {
              step,
              round,
              agent: a.name,
              error: String(e?.stack ?? e),
            });
            throw e;
          }
        }
        jsonl("rounds.jsonl", {
          round,
          step,
          txOk,
          txRejected,
          mismatches,
          elapsedS: Math.round((Date.now() - t0) / 1000),
        });
        // halfway: restart the node on its data directory; sessions held by wallets are gone and must be replaced
        if (!SMOKE && !restarted && round === Math.floor(ROUNDS / 2)) {
          restarted = true;
          await node.stop();
          node.start();
          while ((await node.health()) === null)
            await new Promise((r) => setTimeout(r, 100));
          await verify("node restarted", { restart: true });
          await preseed(PRESEED_HALF, "halfway");
        }
      }
      // everyone claims what is left, so the books close with no memo outstanding
      for (const a of agents) await claimAll(a);

      // a reorganisation is skipped in a smoke run
      if (!SMOKE) {
        // ------------------------------------------------------------ a reorganisation under every wallet
        const snap = await provider.send("evm_snapshot", []);
        const ledgerBefore = new Map(
          [...expectedPublic].map(([k, m]) => [k, new Map(m)]),
        );
        const charlie = byName.get("charlie")!;
        await deposit(charlie, assetA, 777n * UNIT);
        const orphan = [...charlie.notes.values()].sort(
          (p, q) => q.leafIndex - p.leafIndex,
        )[0]!;
        const oldHead = await provider.getBlockNumber();
        await provider.send("evm_revert", [snap]);
        expectedPublic.clear();
        for (const [k, m] of ledgerBefore) expectedPublic.set(k, m);
        // A real reorganisation replaces the dropped blocks with a branch at least as long: mine empty
        // blocks past the old head. The chain now holds fewer leaves, at a later block, than every wallet
        // verified, and each wallet must follow it with no new leaf landing.
        await provider.send("anvil_mine", [
          ethers.toQuantity(oldHead - (await provider.getBlockNumber()) + 1),
        ]);
        const shortCount = Number(await darkPool.getNextLeafIndex());
        const shortHead = await provider.getBlockNumber();
        for (
          let h = await node.health();
          h === null || h.leaves !== shortCount || h.block < shortHead;
          h = await node.health()
        ) {
          await new Promise((r) => setTimeout(r, 20));
        }
        const shortChain: Record<string, string> = {};
        for (const a of agents) {
          try {
            const r = await a.raven.sync();
            shortChain[a.name] =
              `synced at ${r.leafCount}` +
              (r.rewoundTo === undefined ? "" : `, rewound to ${r.rewoundTo}`);
            if (r.leafCount !== shortCount) throw new Error(shortChain[a.name]);
          } catch (e: any) {
            shortChain[a.name] ??= `${e?.kind ?? "error"}: ${e?.message ?? e}`;
            mismatches += 1;
            jsonl("mismatches.jsonl", {
              step,
              label: "reorg: shorter chain not followed",
              agent: a.name,
              want: shortCount,
              got: shortChain[a.name],
            });
          }
        }
        await verify("reorg: the chain is shorter", {
          reorg: true,
          shortChain,
        });
        const orphanGone = ![...charlie.notes.values()].some((n) =>
          n.commitment.equals(orphan.commitment),
        );
        // another user of the pool deposits, which puts a different leaf at the dropped index
        step += 1;
        const od = await makeDeposit(darkPool, token, outsider, 333n * UNIT);
        outsideValue += 333n * UNIT;
        outsiderTx += 1;
        outsiderKinds.reorgDeposit += 1;
        jsonl("transactions.jsonl", {
          step,
          ok: true,
          agent: "outsider",
          kind: "deposit",
          value: 333n * UNIT,
          commitment: od.commitment.toString(),
        });
        await verify("reorg: another user's leaf at the dropped index", {
          reorg: true,
        });
        await deposit(byName.get("david")!, assetA, 333n * UNIT);
        await deposit(byName.get("alice")!, assetA, 111n * UNIT);
        jsonl("reorg.jsonl", {
          orphanLeaf: orphan.leafIndex,
          orphanCommitment: orphan.commitment.toString(),
          orphanGone,
          shortCount,
          shortChain,
        });
        if (!orphanGone) mismatches += 1;
      }

      // ------------------------------------------------------------ scale: a larger pool, then one more round
      if (BULK_TO > 0) {
        await bulk(BULK_TO);
        for (const a of shuffle([...agents])) await act(a);
      }
    } finally {
      await node.stop();
      for (const s of sources) s.close();
    }

    // ------------------------------------------------------------ summary
    const q = (xs: number[], p: number) => {
      const s = [...xs].sort((x, y) => x - y);
      return s.length === 0
        ? 0
        : s[Math.min(s.length - 1, Math.floor(p * (s.length - 1)))]!;
    };
    const routes: Record<string, unknown> = {};
    for (const key of [
      ...new Set(routeSamples.map((r) => `${r.method} ${r.route}`)),
    ]) {
      const xs = routeSamples.filter((r) => `${r.method} ${r.route}` === key);
      const ms = xs.map((r) => r.ms);
      routes[key] = {
        n: xs.length,
        p50: +q(ms, 0.5).toFixed(1),
        p95: +q(ms, 0.95).toFixed(1),
        max: +Math.max(...ms).toFixed(1),
        bytesUp: xs.reduce((s, r) => s + r.up, 0),
        bytesDown: xs.reduce((s, r) => s + r.down, 0),
        statuses: [...new Set(xs.map((r) => r.status))],
        requestSets: [
          ...new Set(xs.flatMap((r) => (r.reqSet === null ? [] : [r.reqSet]))),
        ],
        answerSets: [
          ...new Set(xs.flatMap((r) => (r.ansSet === null ? [] : [r.ansSet]))),
        ],
        bytesUpPerRequest: Math.round(
          xs.reduce((s, r) => s + r.up, 0) / xs.length,
        ),
        bytesDownPerRequest: Math.round(
          xs.reduce((s, r) => s + r.down, 0) / xs.length,
        ),
      };
    }
    const witnesses = agents.flatMap((a) => a.witnesses);
    const summary = {
      seed: SEED,
      rounds: ROUNDS,
      paramSetArg: PARAM_SET === "" ? null : Number(PARAM_SET),
      smoke: SMOKE,
      steps: step,
      transactions: txOk,
      byKind: kinds,
      outsiderTransactions: outsiderTx,
      outsiderByKind: outsiderKinds,
      plantDropFeedLeaf: PLANT_DROP_LEAF < 0 ? null : PLANT_DROP_LEAF,
      plantHits,
      rejected: txRejected,
      rejectedByKind: rejectedKinds,
      mismatches,
      notesPerAgent: Object.fromEntries(
        agents.map((a) => [a.name, a.found().length]),
      ),
      spendsWithRavenPaths: witnesses.length,
      witnessesAllKnownRoots: witnesses.every(
        (w) => w.knownRoot && w.chainRootAtCount,
      ),
      finalLeaves: Number(await darkPool.getNextLeafIndex()),
      nodeStarts: node.starts,
      followLagMs: {
        p50: Math.round(q(followLagMs, 0.5)),
        p95: Math.round(q(followLagMs, 0.95)),
        max: Math.round(Math.max(...followLagMs)),
      },
      walletDiscoveryMs: {
        p50: Math.round(q(discoveryMs, 0.5)),
        p95: Math.round(q(discoveryMs, 0.95)),
        max: Math.round(Math.max(...discoveryMs)),
      },
      // one entry per node process: the run restarts the node halfway
      nodeMemoryKiB: Object.fromEntries(
        [...new Set(memSamples.map((m) => m.start))].map((start) => {
          const xs = memSamples.filter((m) => m.start === start);
          return [
            `process ${start}`,
            {
              samples: xs.length,
              leaves: [xs[0]!.leaves, xs[xs.length - 1]!.leaves],
              sessionsMax: Math.max(...xs.map((m) => m.sessions)),
              firstRss: xs[0]!.rssKiB,
              lastRss: xs[xs.length - 1]!.rssKiB,
              maxRss: Math.max(...xs.map((m) => m.rssKiB)),
              hwm: Math.max(...xs.map((m) => m.hwmKiB)),
            },
          ];
        }),
      ),
      scale: scaleSamples,
      routes,
      wallSeconds: Math.round((Date.now() - t0) / 1000),
    };
    writeFileSync(
      join(OUT, "summary.json"),
      JSON.stringify(
        summary,
        (_, v) => (typeof v === "bigint" ? v.toString() : v),
        2,
      ),
    );
    writeFileSync(
      join(OUT, "route-samples.json"),
      JSON.stringify(routeSamples),
    );

    expect(mismatches, "mismatches (see mismatches.jsonl)").to.equal(0);
    expect(txOk).to.be.greaterThanOrEqual(MIN_TX);
    expect(txRejected).to.be.greaterThan(0);
    expect(witnesses.length).to.be.greaterThan(0);
  });
});
