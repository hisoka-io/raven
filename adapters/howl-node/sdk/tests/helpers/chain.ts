// A local chain (anvil) whose pool emits the fixture's logs, and the node binary following it.
// The pool address carries a small emitter: calldata of 4 bytes answers `getNextLeafIndex()`
// from storage slot 0; any other calldata is a topic count, the topics and the data of one log.
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fixture, type FixtureLog } from "./fixture.js";

const EMITTER =
  "0x3660041460715760003560001a806020026001018036038082600037905081600114603b5781600214604457816003" +
  "1460505781600414605f57005b600135906000a1005b602135600135826000a2005b604135602135600135836000a300" +
  "5b606135604135602135600135846000a4005b60005460005260206000f3";

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolve(typeof address === "object" && address !== null ? address.port : 0));
    });
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Leaves after each fixture block, in fixture order. */
export const countAfter: number[] = (() => {
  let running = 0;
  return fixture.blocks.map((b) => {
    running += b.logs.filter(
      (l) => l.address.toLowerCase() === fixture.pool.toLowerCase() && l.topics[0] === fixture.topics.LeafInserted,
    ).length;
    return running;
  });
})();

export interface Health {
  leaves: number;
  block: number;
  shards: number;
  sessions: number;
}

export class LocalChain {
  readonly rpcUrl: string;
  nodeUrl = "";
  #anvil: ChildProcess;
  #nodes: ChildProcess[] = [];
  readonly #byUrl = new Map<string, ChildProcess>();
  #sender = "";
  #dir: string;
  deploymentBlock = 0;
  leafCount = 0;

  private constructor(port: number, anvil: ChildProcess) {
    this.rpcUrl = `http://127.0.0.1:${port}`;
    this.#anvil = anvil;
    this.#dir = mkdtempSync(join(tmpdir(), "howl-client-live-"));
  }

  static async start(): Promise<LocalChain> {
    const port = await freePort();
    const anvil = spawn("anvil", ["--port", String(port), "--silent"], { stdio: "ignore" });
    const chain = new LocalChain(port, anvil);
    for (let i = 0; i < 200; i++) {
      try {
        await chain.rpc("eth_chainId");
        break;
      } catch {
        await sleep(50);
      }
    }
    if (Number(BigInt(await chain.rpc("eth_chainId"))) !== fixture.chain_id) {
      throw new Error("anvil is not on the fixture's chain id");
    }
    chain.#sender = ((await chain.rpc("eth_accounts")) as string[])[0]!;
    await chain.rpc("anvil_setCode", fixture.pool, EMITTER);
    await chain.rpc("evm_setAutomine", false);
    chain.deploymentBlock = Number(BigInt(await chain.rpc("eth_blockNumber"))) + 1;
    return chain;
  }

  async rpc(method: string, ...params: unknown[]): Promise<any> {
    const response = await fetch(this.rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    const out = (await response.json()) as { result?: unknown; error?: unknown };
    if (out.error !== undefined) throw new Error(`${method}: ${JSON.stringify(out.error)}`);
    return out.result;
  }

  /** Mine one block emitting `logs`, after which the pool holds `leafCount` leaves. */
  async mine(logs: readonly FixtureLog[], leafCount: number): Promise<void> {
    for (const log of logs) {
      const topics = log.topics.map((t) => t.slice(2)).join("");
      const data = "0x" + log.topics.length.toString(16).padStart(2, "0") + topics + log.data.slice(2);
      await this.rpc("eth_sendTransaction", { from: this.#sender, to: fixture.pool, data, gas: "0x1e8480" });
    }
    await this.rpc("evm_mine");
    // anvil writes storage into the newest mined block's state, so the count follows its block
    await this.rpc("anvil_setStorageAt", fixture.pool, "0x0", "0x" + leafCount.toString(16).padStart(64, "0"));
    this.leafCount = leafCount;
  }

  /** Mine fixture blocks `[from, to)`. */
  async mineFixture(from: number, to: number): Promise<void> {
    for (let i = from; i < to; i++) {
      const logs = fixture.blocks[i]!.logs.filter((l) => l.address.toLowerCase() === fixture.pool.toLowerCase());
      await this.mine(logs, countAfter[i]!);
    }
  }

  async head(): Promise<number> {
    return Number(BigInt(await this.rpc("eth_blockNumber")));
  }

  /**
   * Start a node following this chain; the first one started is `nodeUrl`. With `port`, on that
   * port and its data directory, as a restart of the node that ran there.
   */
  async startNode(
    binary: string,
    options: { ttlSecs?: number; paramSet?: number; port?: number } = {},
  ): Promise<string> {
    const port = options.port ?? (await freePort());
    const url = `http://127.0.0.1:${port}`;
    if (this.nodeUrl === "") this.nodeUrl = url;
    const args = [
      "--data-dir", join(this.#dir, `data-${port}`),
      "--chain-id", String(fixture.chain_id),
      "--pool", fixture.pool,
      "--deployment-block", String(this.deploymentBlock),
      "--listen", `127.0.0.1:${port}`,
      "--poll-ms", "100",
      "--max-range", "10",
      ...(options.ttlSecs === undefined ? [] : ["--session-ttl-secs", String(options.ttlSecs)]),
      ...(options.paramSet === undefined ? [] : ["--param-set", String(options.paramSet)]),
    ];
    const node = spawn(binary, args, {
      env: { ...process.env, HOWL_NODE_RPC_URL: this.rpcUrl, RUST_LOG: "warn" },
      stdio: "ignore",
    });
    this.#nodes.push(node);
    this.#byUrl.set(url, node);
    return url;
  }

  /** Stop the node at `url` and start it again on the same port and data, with `options`. */
  async restartNode(url: string, binary: string, options: { paramSet?: number } = {}): Promise<void> {
    const node = this.#byUrl.get(url);
    if (node === undefined) throw new Error(`no node at ${url}`);
    if (node.exitCode === null) {
      const exited = new Promise((r) => node.once("exit", r));
      node.kill("SIGINT");
      await exited;
    }
    await this.startNode(binary, { ...options, port: Number(new URL(url).port) });
  }

  async health(url = this.nodeUrl): Promise<Health | null> {
    try {
      const response = await fetch(`${url}/howl/v1/health`);
      if (response.status !== 200) return null;
      const fields = Object.fromEntries(
        (await response.text())
          .trim()
          .split(/\s+/)
          .slice(1)
          .map((kv) => kv.split("=") as [string, string]),
      );
      return {
        leaves: Number(fields.leaves),
        block: Number(fields.block),
        shards: Number(fields.shards),
        sessions: Number(fields.sessions),
      };
    } catch {
      return null;
    }
  }

  /** Wait until the node serves the chain's head with `leaves` leaves. */
  async caughtUp(leaves = this.leafCount, url = this.nodeUrl, timeoutMs = 60_000): Promise<Health> {
    const head = await this.head();
    const start = Date.now();
    for (;;) {
      const h = await this.health(url);
      if (h !== null && h.leaves === leaves && h.block === head) return h;
      if (Date.now() - start > timeoutMs) {
        throw new Error(`node not at ${leaves} leaves / block ${head}: ${JSON.stringify(h)}`);
      }
      await sleep(50);
    }
  }

  async stop(): Promise<void> {
    for (const node of this.#nodes) {
      if (node.exitCode === null) {
        node.kill("SIGINT");
        await new Promise((r) => node.once("exit", r));
      }
    }
    this.#anvil.kill("SIGTERM");
    rmSync(this.#dir, { recursive: true, force: true });
  }
}
