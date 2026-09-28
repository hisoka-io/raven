// Stub-driven suites read batch replies through a shared helper, so every conclusion they draw
// rests on that helper matching the SDK's own reader. A drifted helper fails nothing on its own.

import { describe, expect, it } from "vitest";

import { RavenPOINodeInterface, TREE_DEPTH } from "../src/index";
import { TOKEN, encodeBatchResponseNodes, stubCtx } from "./helpers/auth_path_stub";
import { forestConfig } from "./helpers/forest";
import { startMockServer } from "./helpers/mock_server";
import { PATH10_ROW_BYTES, path10Root, path10Slot } from "./helpers/path10_row";

const LIST_KEY_HEX = "ab".repeat(32);

describe("shared batch-response encoder round-trips through the SDK's own decode", () => {
  // Suites serve batch replies through encodeBatchResponseNodes; this pins that ONE writer to
  // the real reader (stripSchemaEnvelope, decodeBatchBody and the addendum split in
  // src/raven-poi-node-interface.ts) byte for byte, so the helper tracks the wire shape the
  // server speaks rather than a memory of it.
  it("every node byte comes back as the corresponding auth-path element", async () => {
    const server = await startMockServer();
    try {
      const bcHex = "0e".repeat(32);
      const nodes = Array.from({ length: TREE_DEPTH }, (_unused, i) => {
        const node = new Uint8Array(32);
        node[0] = 0x10 + i;
        node[15] = 0xa5;
        node[31] = 0xee;
        return node;
      });
      server.route(
        (req) => /^\/v1\/instance\/[^/]+\/batch$/.test(req.url ?? ""),
        (_req, _body, res) => {
          res.writeHead(200, {
            "content-type": "application/octet-stream",
            "x-raven-freshness": "lag_blocks=0 applied_height=0 epoch=1 confidence=1",
          });
          res.end(Buffer.from(encodeBatchResponseNodes([path10Slot({ bcHex, nodes })])));
          return true;
        },
      );
      const sdk = new RavenPOINodeInterface({
        ...forestConfig({
          endpoint: server.url,
          listKeyHex: LIST_KEY_HEX,
          ctx: { ...stubCtx(), entrySize: PATH10_ROW_BYTES },
          placed: [[bcHex, 5]],
          pins: new Map([[0, path10Root(bcHex, nodes, 5)]]),
        }),
        bearerToken: TOKEN,
      });
      const [proof] = await sdk.getPOIMerkleProofs(LIST_KEY_HEX, [bcHex]);
      expect(proof.elements).toHaveLength(TREE_DEPTH);
      const hex = (b: Uint8Array): string =>
        Array.from(b)
          .map((v) => v.toString(16).padStart(2, "0"))
          .join("");
      for (let i = 0; i < TREE_DEPTH; i += 1) {
        expect(proof.elements[i], `level ${i}`).toBe(hex(nodes[i]));
      }
    } finally {
      await server.close();
    }
  });
});
