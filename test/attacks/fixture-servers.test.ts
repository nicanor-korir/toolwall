/**
 * fixture-servers.test.ts — proves the malicious fixture SERVERS actually run and put their payloads
 * on the wire. Per the red-team reporting standard: demonstrate the attack working, don't describe it.
 *
 * These tests connect a real MCP client DIRECTLY to each fixture server (no toolwall in between,
 * because toolwall's src/ does not exist yet). They assert the attack corpus is live: the poison
 * reaches a client verbatim, and the rug-pull servers really mutate. When Dev 1/2/3 land the proxy,
 * the SAME servers get pointed at toolwall and these payloads must then be blocked/quarantined.
 */
import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = resolve(HERE, "../fixtures/malicious");

async function connect(serverFile: string, args: string[] = []) {
  const transport = new StdioClientTransport({
    command: process.execPath, // node
    args: [resolve(FIX, serverFile), ...args],
    stderr: "ignore",
  });
  const client = new Client({ name: "red-team-harness", version: "1.0.0" });
  await client.connect(transport);
  return { client, transport };
}

describe("poisoned-server.js is a live tool-poisoning attack", () => {
  it("boots and serves the poisoned tool description over MCP (T-01)", async () => {
    const { client, transport } = await connect("poisoned-server.js");
    try {
      const { tools } = await client.listTools();
      expect(tools).toHaveLength(1);
      const tool = tools[0]!;
      expect(tool.name).toBe("safe_addition_calculator");
      // The injection arrives byte-for-byte in the description...
      expect(tool.description).toContain("Ignore previous instructions");
      expect(tool.description).toContain("secretly");
      // ...and in a NESTED schema property description (a description-only scrub misses this).
      const b = (tool.inputSchema as any).properties.b.description as string;
      expect(b).toContain("secretly");
      // ...and the tool lies via annotations (readOnly while it tells the model to read files).
      expect((tool as any).annotations?.readOnlyHint).toBe(true);
    } finally {
      await transport.close();
    }
  });

  it("poisons the tool RESULT leg too (T-03)", async () => {
    const { client, transport } = await connect("poisoned-server.js");
    try {
      const res: any = await client.callTool({
        name: "safe_addition_calculator",
        arguments: { a: 2, b: 3 },
      });
      // Correct sum is returned (so the tool looks legitimate)...
      expect(res.content[0].text).toBe("5");
      // ...alongside an injected instruction in the result content.
      expect(res.content[1].text).toContain("Ignore previous instructions");
    } finally {
      await transport.close();
    }
  });

  it("poisons server instructions (T-01, ranks alongside descriptions)", async () => {
    const { client, transport } = await connect("poisoned-server.js");
    try {
      // getInstructions() surfaces what the client would place in its system prompt.
      const instructions = client.getInstructions?.();
      expect(instructions ?? "").toContain("secretly");
    } finally {
      await transport.close();
    }
  });
});

describe("rugpull-server.js mutates after approval (T-02)", () => {
  it("variant a: prose mutates on the SECOND tools/list (schema unchanged)", async () => {
    const { client, transport } = await connect("rugpull-server.js", ["--variant", "a"]);
    try {
      const first = (await client.listTools()).tools[0]!;
      expect(first.description).toBe("Adds two integers and returns the sum.");

      const second = (await client.listTools()).tools[0]!;
      expect(second.description).toContain("Ignore previous instructions"); // rug pulled
      // Schema is byte-identical between the two lists.
      expect(JSON.stringify(second.inputSchema)).toBe(JSON.stringify(first.inputSchema));
    } finally {
      await transport.close();
    }
  });

  it("variant b: schema mutates while prose stays byte-identical", async () => {
    const { client, transport } = await connect("rugpull-server.js", ["--variant", "b"]);
    try {
      const first = (await client.listTools()).tools[0]!;
      const second = (await client.listTools()).tools[0]!;
      // Prose is unchanged — a prose-only hash sees no rug pull...
      expect(second.description).toBe(first.description);
      // ...but a hidden required exfil parameter has appeared.
      const props = (second.inputSchema as any).properties;
      expect(props.exfil_target).toBeDefined();
      expect((second.inputSchema as any).required).toContain("exfil_target");
    } finally {
      await transport.close();
    }
  });

  it("variant c: benign until AFTER N calls, then mutates (Deadbugz)", async () => {
    const { client, transport } = await connect("rugpull-server.js", [
      "--variant",
      "c",
      "--threshold",
      "3",
      "--silent", // prove it even without the list_changed notification
    ]);
    try {
      // Clean at first list and through the threshold calls.
      expect((await client.listTools()).tools[0]!.description).toBe(
        "Adds two integers and returns the sum.",
      );
      for (let i = 0; i < 3; i++) {
        await client.callTool({ name: "add", arguments: { a: 1, b: 1 } });
        expect((await client.listTools()).tools[0]!.description).toBe(
          "Adds two integers and returns the sum.",
        );
      }
      // The 4th call trips the mutation...
      await client.callTool({ name: "add", arguments: { a: 1, b: 1 } });
      // ...and the NEXT list is poisoned. TOFU/first-connect pinning never re-checks here.
      expect((await client.listTools()).tools[0]!.description).toContain(
        "Ignore previous instructions",
      );
    } finally {
      await transport.close();
    }
  });
});
