/**
 * Header/body agreement for Streamable HTTP — the intermediary obligation.
 *
 * WHY A PROXY MUST DO THIS, STATED AS AN ATTACK
 * ---------------------------------------------
 * `2026-07-28` requires clients to mirror body fields into headers so that an
 * intermediary can route and police traffic without parsing bodies
 * (`docs/RESEARCH-BRIEF.md` §1.7):
 *
 * | header                 | mirrors                                              |
 * |------------------------|------------------------------------------------------|
 * | `MCP-Protocol-Version` | `_meta["io.modelcontextprotocol/protocolVersion"]`   |
 * | `Mcp-Method`           | `method`                                             |
 * | `Mcp-Name`             | `params.name` (tools/call, prompts/get) / `params.uri` (resources/read) |
 * | `Mcp-Param-{Name}`     | the named entry of `params.arguments`                |
 *
 * The moment two places can describe one request, they can describe it
 * differently. Akamai's header-confusion work is the general form: conflicting
 * header and body values make a proxy and a backend interpret a single request
 * two ways, and every control that lives on the proxy's reading is bypassed by
 * the backend's. Concretely here:
 *
 * ```http
 * POST /mcp
 * Mcp-Method: tools/list          <- what the policy engine sees
 * Mcp-Name: read_file
 *
 * {"method":"tools/call","params":{"name":"delete_everything", … }}
 *                                 <- what actually executes
 * ```
 *
 * A proxy that authorises on `Mcp-Name` and forwards the body has not enforced
 * anything; it has published an oracle for how to phrase a bypass. **Splitting
 * policy evaluation from execution is not a bug in the deployment, it is the
 * shape of the feature**, and the only safe posture for an intermediary is to
 * refuse to serve a request whose two descriptions differ.
 *
 * The spec says so directly, twice over. Mismatch is `400` plus JSON-RPC
 * `-32020 HeaderMismatch`. And, the mandate aimed squarely at us: an
 * intermediary enforcing policy on mirrored headers **SHOULD verify
 * `MCP-Protocol-Version` indicates a revision that requires header-body
 * validation, and SHOULD reject the request otherwise rather than trusting
 * unvalidated headers.** A `2025-11-25` request has no mirroring obligation at
 * all, so its headers are decoration an attacker writes for free — we answer
 * `-32022 UnsupportedProtocolVersion` rather than policing a fiction.
 *
 * DESIGN RULES IN THIS FILE
 * -------------------------
 * 1. **Compare, never reconcile.** No trimming, no case folding, no Unicode
 *    normalization, no "close enough". Every normalization step is a way for
 *    two parties to reach different conclusions about the same bytes, which is
 *    the vulnerability class itself.
 * 2. **Decode the sentinel before comparing, and only the exact sentinel.**
 *    `=?base64?…?=` is lowercase and case-sensitive, so `=?BASE64?…?=` is a
 *    literal value, not an encoding. A proxy that decoded it leniently while
 *    the backend did not would reintroduce the split it is here to prevent.
 * 3. **Repeated headers are a rejection, never a choice.** Two `Mcp-Name`
 *    values force every hop to pick one, and hops that pick differently is
 *    request smuggling with extra steps.
 * 4. **Missing required header is a rejection.** "Absent" must not be a way to
 *    opt out of validation; that would make the control advisory.
 * 5. **Batches are rejected.** One header set cannot honestly describe N
 *    messages.
 *
 * STATUS — SAY THIS PLAINLY
 * -------------------------
 * **This is now on a live path.** `src/transport/listener.ts` calls
 * `verifyHeaderBodyAgreement` on every POST before the body reaches the guard
 * pipeline, and answers `400` with the `-32020` body this file builds when the
 * two descriptions disagree. Under `2025-11-25`, which mandates no mirroring,
 * the check runs only when a request actually carries `Mcp-Method`, `Mcp-Name`
 * or `Mcp-Param-*` — see {@link hasMirroredPolicyHeaders} — and then answers
 * `-32022`, because policing headers whose correctness nothing requires is the
 * failure this file exists to prevent, not a service.
 *
 * The earlier note here said toolwall shipped no HTTP listener and that this
 * module had no live consumer. That was true and is no longer; the
 * classification in `test/integration/wiring-completeness.test.ts` moved from
 * `exported-only` to `support` in the same change, which is exactly the failure
 * that check was written to force.
 */

import { MCP_HEADER_MISMATCH, MCP_UNSUPPORTED_PROTOCOL_VERSION } from '../types/protocol.js';

// ---------------------------------------------------------------------------
// Header names
// ---------------------------------------------------------------------------

export const HEADER_PROTOCOL_VERSION = 'mcp-protocol-version';
export const HEADER_METHOD = 'mcp-method';
export const HEADER_NAME = 'mcp-name';
export const HEADER_PARAM_PREFIX = 'mcp-param-';

/** `_meta` key the `MCP-Protocol-Version` header mirrors (§1.7, §1.10). */
export const META_PROTOCOL_VERSION = 'io.modelcontextprotocol/protocolVersion';

/**
 * Revisions that mandate header/body mirroring, and therefore the only
 * revisions whose mirrored headers an intermediary may police.
 */
export const HEADER_VALIDATING_REVISIONS: readonly string[] = Object.freeze(['2026-07-28']);

/** Which methods carry a `Mcp-Name`, and which body field it mirrors (§1.7). */
const NAME_BEARING_METHODS: ReadonlyMap<string, 'name' | 'uri'> = new Map([
    ['tools/call', 'name'],
    ['prompts/get', 'name'],
    ['resources/read', 'uri']
]);

// ---------------------------------------------------------------------------
// The `=?base64?…?=` sentinel
// ---------------------------------------------------------------------------

const SENTINEL_PREFIX = '=?base64?';
const SENTINEL_SUFFIX = '?=';

/**
 * Values that cannot travel raw in an HTTP field and MUST use the sentinel:
 * anything non-ASCII, any control character, and space.
 */
export function needsSentinel(value: string): boolean {
    // eslint-disable-next-line no-control-regex -- matching control chars is the point
    return /[^\x21-\x7e]/u.test(value);
}

export function encodeMirroredHeaderValue(value: string): string {
    if (!needsSentinel(value)) {
        return value;
    }
    return `${SENTINEL_PREFIX}${Buffer.from(value, 'utf8').toString('base64')}${SENTINEL_SUFFIX}`;
}

export type SentinelDecode =
    | { readonly ok: true; readonly value: string; readonly encoded: boolean }
    | { readonly ok: false; readonly reason: string };

/**
 * Decode a mirrored header value.
 *
 * The markers are lowercase and case-sensitive, so `=?BASE64?zzz?=` decodes to
 * itself — it is a literal, and if the body does not contain that literal the
 * request is a mismatch. That is the strict reading and it is the safe one: the
 * alternative is a proxy that sees one value where the backend sees another.
 *
 * A malformed payload inside a well-formed sentinel is an error, not a
 * fallback to the raw string. Falling back would let an attacker choose which
 * interpretation each hop reaches by supplying base64 that only some decoders
 * accept.
 */
export function decodeMirroredHeaderValue(raw: string): SentinelDecode {
    if (!raw.startsWith(SENTINEL_PREFIX) || !raw.endsWith(SENTINEL_SUFFIX)) {
        return { ok: true, value: raw, encoded: false };
    }
    const inner = raw.slice(SENTINEL_PREFIX.length, raw.length - SENTINEL_SUFFIX.length);
    if (inner.length === 0) {
        return { ok: true, value: '', encoded: true };
    }
    if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(inner)) {
        return { ok: false, reason: 'sentinel payload is not base64' };
    }
    const decoded = Buffer.from(inner, 'base64');
    // Node's base64 decoder is permissive — it accepts unpadded input, and it
    // ignores trailing garbage bits. Re-encoding and demanding byte equality
    // *including padding* leaves exactly one spelling per value. Accepting two
    // spellings is accepting that two hops may read the same header differently,
    // which is the whole vulnerability class this file exists for.
    if (decoded.toString('base64') !== inner) {
        return { ok: false, reason: 'sentinel payload is not canonical padded base64' };
    }
    const text = decoded.toString('utf8');
    if (Buffer.compare(Buffer.from(text, 'utf8'), decoded) !== 0) {
        return { ok: false, reason: 'sentinel payload is not valid UTF-8' };
    }
    return { ok: true, value: text, encoded: true };
}

// ---------------------------------------------------------------------------
// Input shapes
// ---------------------------------------------------------------------------

export type IncomingHeaderValue = string | readonly string[] | undefined;
export type IncomingHeaders = Readonly<Record<string, IncomingHeaderValue>>;

/**
 * Does this request carry any header an intermediary would evaluate policy ON?
 *
 * `MCP-Protocol-Version` is deliberately NOT one of them: it is sent by every revision from
 * `2025-03-26` onwards and says nothing about what the request does, so treating its presence as
 * "the client opted into mirroring" would make every legacy request fail validation.
 *
 * The three that ARE policy input are `Mcp-Method`, `Mcp-Name` and `Mcp-Param-*`. A live front
 * door uses this to decide *whether* to run {@link verifyHeaderBodyAgreement} at all under a
 * revision that does not mandate mirroring: absent, there is nothing to disagree with the body and
 * the request is judged on its body alone; present, they must be checked, and under a revision
 * with no mirroring obligation the honest answer is `-32022` — we will not police headers whose
 * correctness nothing requires.
 */
export function hasMirroredPolicyHeaders(headers: IncomingHeaders): boolean {
    for (const key of Object.keys(headers)) {
        const lower = key.toLowerCase();
        if (lower === HEADER_METHOD || lower === HEADER_NAME || lower.startsWith(HEADER_PARAM_PREFIX)) {
            return true;
        }
    }
    return false;
}

export interface HeaderViolation {
    readonly ruleId: string;
    readonly header: string;
    readonly message: string;
    readonly remediation: string;
}

export interface HeaderCheckOk {
    readonly ok: true;
    /** The agreed protocol version. Safe to route on: header and body concur. */
    readonly protocolVersion: string;
    /** The agreed method. Safe to authorise on. */
    readonly method: string;
    /** The agreed `params.name` / `params.uri`, when the method carries one. */
    readonly name?: string;
    /** Agreed `Mcp-Param-*` values, keyed by the argument name from the body. */
    readonly params: Readonly<Record<string, string>>;
}

export interface HeaderCheckFailed {
    readonly ok: false;
    /** `-32020 HeaderMismatch` or `-32022 UnsupportedProtocolVersion`. */
    readonly code: number;
    /** The spec pairs both refusals with HTTP `400`. */
    readonly httpStatus: 400;
    readonly violations: readonly HeaderViolation[];
    /**
     * A JSON-RPC error object ready to write to the response body.
     *
     * `data` carries only toolwall-authored rule ids and header names. It does
     * **not** echo the offending values: the mismatch is between two things the
     * caller already knows, and quoting them back is how an error becomes an
     * oracle for probing what the intermediary accepts (same reasoning as
     * `redactFindingForClient` in `./proxy.ts`).
     */
    readonly error: {
        readonly code: number;
        readonly message: string;
        readonly data: { readonly toolwall: { readonly headerMismatch: true; readonly violations: readonly string[] } };
    };
}

export type HeaderCheck = HeaderCheckOk | HeaderCheckFailed;

export interface HeaderCheckOptions {
    /** Override the revisions considered to mandate mirroring. */
    readonly validatingRevisions?: readonly string[];
    /**
     * Reject a request whose declared revision does not mandate mirroring.
     * Defaults to `true`, which is the spec's SHOULD. Turning it off means
     * trusting unvalidated headers, which is the thing this file exists to
     * prevent; it exists only so a deployment that terminates policy elsewhere
     * can say so explicitly.
     */
    readonly requireValidatingRevision?: boolean;
}

// ---------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * Read one header, insisting it appears exactly once.
 *
 * `undefined` means absent. `null` means "present more than once", which is
 * always a rejection — see design rule 3.
 */
function single(headers: IncomingHeaders, lowerName: string): string | undefined | null {
    let found: string | undefined;
    let count = 0;
    for (const [key, value] of Object.entries(headers)) {
        if (key.toLowerCase() !== lowerName) {
            continue;
        }
        if (Array.isArray(value)) {
            count += value.length;
            found = value[0];
        } else if (typeof value === 'string') {
            count += 1;
            found = value;
        }
    }
    if (count === 0) return undefined;
    if (count > 1) return null;
    return found;
}

function mismatch(violations: readonly HeaderViolation[], code: number, message: string): HeaderCheckFailed {
    return {
        ok: false,
        code,
        httpStatus: 400,
        violations,
        error: {
            code,
            message,
            data: { toolwall: { headerMismatch: true, violations: violations.map(v => v.ruleId) } }
        }
    };
}

/**
 * Verify that the mirrored headers and the JSON-RPC body describe the same
 * request.
 *
 * `body` is the already-parsed JSON-RPC message. Parsing it is unavoidable —
 * the whole point is that the intermediary must not take the headers' word for
 * what it says. The headers buy routing cheapness, not the right to skip the
 * body.
 */
export function verifyHeaderBodyAgreement(
    headers: IncomingHeaders,
    body: unknown,
    options: HeaderCheckOptions = {}
): HeaderCheck {
    const violations: HeaderViolation[] = [];
    const add = (ruleId: string, header: string, message: string, remediation: string): void => {
        violations.push({ ruleId, header, message, remediation });
    };

    // --- one message, not a batch -----------------------------------------
    if (Array.isArray(body)) {
        add(
            'toolwall/header-batch-unvalidatable',
            HEADER_METHOD,
            'The body is a JSON-RPC batch, so one set of mirrored headers cannot describe it.',
            'Send one JSON-RPC message per POST, as the 2026-07-28 Streamable HTTP transport expects.'
        );
        return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: mirrored headers cannot describe a batch body');
    }
    if (!isRecord(body)) {
        add(
            'toolwall/header-body-unparseable',
            HEADER_METHOD,
            'The body is not a JSON-RPC object, so there is nothing to check the headers against.',
            'Send a single JSON-RPC object.'
        );
        return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: body is not a JSON-RPC object');
    }

    // --- protocol version gate -------------------------------------------
    // Done FIRST and on its own: everything below is only meaningful if this
    // revision actually obliges the client to have mirrored anything.
    const validating = options.validatingRevisions ?? HEADER_VALIDATING_REVISIONS;
    const rawVersion = single(headers, HEADER_PROTOCOL_VERSION);
    if (rawVersion === null) {
        add(
            'toolwall/header-repeated',
            HEADER_PROTOCOL_VERSION,
            'MCP-Protocol-Version appears more than once.',
            'Send exactly one MCP-Protocol-Version header; repeated headers make hops disagree.'
        );
        return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: MCP-Protocol-Version is repeated');
    }
    if (rawVersion === undefined) {
        add(
            'toolwall/header-protocol-version-absent',
            HEADER_PROTOCOL_VERSION,
            'MCP-Protocol-Version is absent, so this intermediary cannot establish that the mirrored headers were validated at all.',
            'Send MCP-Protocol-Version on every POST, mirroring _meta["io.modelcontextprotocol/protocolVersion"].'
        );
        return mismatch(
            violations,
            MCP_UNSUPPORTED_PROTOCOL_VERSION,
            'toolwall: refusing to police mirrored headers without a declared protocol version'
        );
    }

    const decodedVersion = decodeMirroredHeaderValue(rawVersion);
    if (!decodedVersion.ok) {
        add(
            'toolwall/header-sentinel-malformed',
            HEADER_PROTOCOL_VERSION,
            `MCP-Protocol-Version uses the =?base64?…?= sentinel but ${decodedVersion.reason}.`,
            'Encode the value as canonical base64 of its UTF-8 bytes, or send it raw if it is printable ASCII.'
        );
        return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: MCP-Protocol-Version sentinel is malformed');
    }

    const bodyMeta = isRecord(body['params']) ? (body['params'] as Record<string, unknown>)['_meta'] : undefined;
    const bodyVersion = isRecord(bodyMeta) ? bodyMeta[META_PROTOCOL_VERSION] : undefined;
    if (typeof bodyVersion === 'string' && bodyVersion !== decodedVersion.value) {
        // The nastiest case in the whole file: policy would run against the
        // header's revision while the server executes under the body's.
        add(
            'toolwall/header-body-protocol-version-mismatch',
            HEADER_PROTOCOL_VERSION,
            'MCP-Protocol-Version disagrees with _meta["io.modelcontextprotocol/protocolVersion"] in the body.',
            'Mirror the body value exactly. Two revisions for one request is a policy/execution split.'
        );
        return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: MCP-Protocol-Version disagrees with the body');
    }

    if ((options.requireValidatingRevision ?? true) && !validating.includes(decodedVersion.value)) {
        add(
            'toolwall/header-revision-does-not-validate',
            HEADER_PROTOCOL_VERSION,
            `Revision ${JSON.stringify(decodedVersion.value)} does not require header-body validation, so its mirrored headers are unverified input.`,
            `Speak a revision that mandates mirroring (${validating.join(', ')}), or enforce policy on the body only.`
        );
        return mismatch(
            violations,
            MCP_UNSUPPORTED_PROTOCOL_VERSION,
            'toolwall: refusing to enforce policy on mirrored headers for a revision that does not require validating them'
        );
    }

    // --- notifications carry no method mirroring obligation ---------------
    const bodyMethod = body['method'];
    const isRequest = 'id' in body && body['id'] !== undefined && body['id'] !== null;
    if (typeof bodyMethod !== 'string') {
        // A response travelling through: no `method` to mirror. Nothing to check.
        return { ok: true, protocolVersion: decodedVersion.value, method: '', params: {} };
    }

    // --- Mcp-Method -------------------------------------------------------
    const rawMethod = single(headers, HEADER_METHOD);
    if (rawMethod === null) {
        add('toolwall/header-repeated', HEADER_METHOD, 'Mcp-Method appears more than once.', 'Send exactly one Mcp-Method header.');
        return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: Mcp-Method is repeated');
    }
    if (rawMethod === undefined) {
        if (isRequest) {
            add(
                'toolwall/header-method-absent',
                HEADER_METHOD,
                'Mcp-Method is required on requests under this revision and is absent.',
                'Mirror the body `method` into Mcp-Method. Absence must not be a way to skip validation.'
            );
            return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: Mcp-Method is absent');
        }
        // Notification with no mirrored method: nothing further to compare.
        return { ok: true, protocolVersion: decodedVersion.value, method: bodyMethod, params: {} };
    }
    const decodedMethod = decodeMirroredHeaderValue(rawMethod);
    if (!decodedMethod.ok) {
        add(
            'toolwall/header-sentinel-malformed',
            HEADER_METHOD,
            `Mcp-Method uses the sentinel but ${decodedMethod.reason}.`,
            'Encode the value as canonical base64 of its UTF-8 bytes.'
        );
        return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: Mcp-Method sentinel is malformed');
    }
    if (decodedMethod.value !== bodyMethod) {
        add(
            'toolwall/header-body-method-mismatch',
            HEADER_METHOD,
            'Mcp-Method disagrees with the JSON-RPC `method` in the body.',
            'Mirror the body value exactly. A proxy authorising the header while the server runs the body enforces nothing.'
        );
        return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: Mcp-Method disagrees with the body');
    }

    // --- Mcp-Name ---------------------------------------------------------
    const params = isRecord(body['params']) ? (body['params'] as Record<string, unknown>) : undefined;
    const nameField = NAME_BEARING_METHODS.get(bodyMethod);
    const rawName = single(headers, HEADER_NAME);
    if (rawName === null) {
        add('toolwall/header-repeated', HEADER_NAME, 'Mcp-Name appears more than once.', 'Send exactly one Mcp-Name header.');
        return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: Mcp-Name is repeated');
    }

    let agreedName: string | undefined;
    if (nameField !== undefined) {
        const bodyName = params?.[nameField];
        if (rawName === undefined) {
            add(
                'toolwall/header-name-absent',
                HEADER_NAME,
                `Mcp-Name is required for ${bodyMethod} under this revision and is absent.`,
                `Mirror params.${nameField} into Mcp-Name.`
            );
            return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: Mcp-Name is absent');
        }
        const decodedName = decodeMirroredHeaderValue(rawName);
        if (!decodedName.ok) {
            add(
                'toolwall/header-sentinel-malformed',
                HEADER_NAME,
                `Mcp-Name uses the sentinel but ${decodedName.reason}.`,
                'Encode the value as canonical base64 of its UTF-8 bytes.'
            );
            return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: Mcp-Name sentinel is malformed');
        }
        if (typeof bodyName !== 'string' || decodedName.value !== bodyName) {
            add(
                'toolwall/header-body-name-mismatch',
                HEADER_NAME,
                `Mcp-Name disagrees with params.${nameField} in the body.`,
                'Mirror the body value exactly. This is the tool-name confusion case: policy on the header, execution on the body.'
            );
            return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: Mcp-Name disagrees with the body');
        }
        agreedName = decodedName.value;
    } else if (rawName !== undefined) {
        add(
            'toolwall/header-name-unexpected',
            HEADER_NAME,
            `Mcp-Name was sent for ${bodyMethod}, which mirrors no name field, so nothing in the body constrains it.`,
            'Do not send Mcp-Name for methods that have no name to mirror; an unconstrained header is free-form input to any policy that reads it.'
        );
        return mismatch(violations, MCP_HEADER_MISMATCH, 'toolwall: Mcp-Name was sent for a method that mirrors none');
    }

    // --- Mcp-Param-{Name} -------------------------------------------------
    const args = isRecord(params?.['arguments']) ? (params['arguments'] as Record<string, unknown>) : undefined;
    const agreedParams: Record<string, string> = {};
    for (const key of Object.keys(headers)) {
        const lower = key.toLowerCase();
        if (!lower.startsWith(HEADER_PARAM_PREFIX)) {
            continue;
        }
        const suffix = lower.slice(HEADER_PARAM_PREFIX.length);
        const raw = single(headers, lower);
        if (raw === null) {
            add('toolwall/header-repeated', key, `${key} appears more than once.`, 'Send exactly one header per mirrored argument.');
            return mismatch(violations, MCP_HEADER_MISMATCH, `toolwall: ${key} is repeated`);
        }
        if (raw === undefined) {
            continue;
        }
        const decoded = decodeMirroredHeaderValue(raw);
        if (!decoded.ok) {
            add('toolwall/header-sentinel-malformed', key, `${key} uses the sentinel but ${decoded.reason}.`, 'Encode the value as canonical base64 of its UTF-8 bytes.');
            return mismatch(violations, MCP_HEADER_MISMATCH, `toolwall: ${key} sentinel is malformed`);
        }

        // HTTP header names are case-insensitive; MCP argument names are not.
        // Resolve to exactly one argument or reject: "which of `Path` and `path`
        // did the header mean" is a question two hops can answer differently.
        const candidates = Object.keys(args ?? {}).filter(name => name.toLowerCase() === suffix);
        if (candidates.length !== 1) {
            add(
                'toolwall/header-param-unresolvable',
                key,
                candidates.length === 0
                    ? `${key} names an argument that is not present in params.arguments.`
                    : `${key} matches ${candidates.length} arguments case-insensitively, so which one it mirrors is ambiguous.`,
                'Mirror only arguments whose names are unambiguous when lowercased, and only when the argument is actually present.'
            );
            return mismatch(violations, MCP_HEADER_MISMATCH, `toolwall: ${key} does not resolve to one argument`);
        }
        const argName = candidates[0] as string;
        const argValue = args?.[argName];
        if (typeof argValue !== 'string' || argValue !== decoded.value) {
            add(
                'toolwall/header-body-param-mismatch',
                key,
                `${key} disagrees with params.arguments.${argName} in the body.`,
                'Mirror the body value exactly, or omit the header.'
            );
            return mismatch(violations, MCP_HEADER_MISMATCH, `toolwall: ${key} disagrees with the body`);
        }
        agreedParams[argName] = decoded.value;
    }

    return {
        ok: true,
        protocolVersion: decodedVersion.value,
        method: bodyMethod,
        ...(agreedName !== undefined ? { name: agreedName } : {}),
        params: agreedParams
    };
}

/**
 * The headers a conforming client would have sent for this body.
 *
 * Exists so a toolwall HTTP client leg can *emit* correct mirroring when it
 * forwards, and so a test can round-trip `build -> verify` rather than asserting
 * against hand-written strings that could encode the same misunderstanding
 * twice.
 */
export function mirroredHeadersForBody(body: unknown, protocolVersion: string): Record<string, string> {
    const out: Record<string, string> = {
        'MCP-Protocol-Version': encodeMirroredHeaderValue(protocolVersion)
    };
    if (!isRecord(body)) {
        return out;
    }
    const method = body['method'];
    if (typeof method !== 'string') {
        return out;
    }
    out['Mcp-Method'] = encodeMirroredHeaderValue(method);
    const params = isRecord(body['params']) ? (body['params'] as Record<string, unknown>) : undefined;
    const nameField = NAME_BEARING_METHODS.get(method);
    if (nameField !== undefined && typeof params?.[nameField] === 'string') {
        out['Mcp-Name'] = encodeMirroredHeaderValue(params[nameField] as string);
    }
    return out;
}
