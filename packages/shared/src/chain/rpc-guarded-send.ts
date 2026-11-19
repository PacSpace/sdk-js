import { makeError, type FetchGetUrlFunc, type FetchRequest } from "ethers";
import { isMirrorRedirect, MIRROR_ANSWER_MAX_BYTES, mirrorRefusalOf, readMirrorText, rpcRefusal } from "../records/ledger-write-search-v1";
import { replaceRpcSecrets, rpcUrlSecrets } from "./rpc-provider";

/**
 * How a reader sends to a JSON-RPC endpoint it was pointed at (a checker's
 * `--rpc`, an SDK `source`): held to its own address, its answers to a size
 * and its waits to an end, as a mirror source is.
 *
 * ethers' own sender follows a 301, 302, 307 or 308 to any host and sends the
 * request body again, reads an answer whole and inflates a compressed one in
 * one step, and on a 429 waits whatever `retry-after` names. A provider that
 * serves PacSpace's own traffic (API, worker, indexer) keeps ethers' sender;
 * only a reader passes `holdRpcRequest` to `createRpcProvider`.
 */

/** A reader's request is tried this many times in all when the endpoint answers 429. */
export const RPC_READER_MAX_TRIES = 3;

export interface GuardedRpcSendOptions {
  /** The most bytes of one answer that are read, counted after decompression. */
  maxBytes?: number;
  fetchImpl?: typeof fetch;
}

function basicAuthorization(username: string, password: string): string {
  const decoded = (value: string) => {
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  };
  const bytes = new TextEncoder().encode(`${decoded(username)}:${decoded(password)}`);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return `Basic ${btoa(binary)}`;
}

/**
 * The request function for ethers' `FetchRequest.getUrlFunc`. One request to
 * the address it is given and nowhere else: a redirect (any 3xx, or a
 * browser's opaque redirect) is refused, never followed; the answer is read
 * no further than `maxBytes`, counted after decompression; the request ends
 * at the request's own timeout. User info in the address is sent as a basic
 * authorization header to that address only, since `fetch` refuses an address
 * that carries it. A refusal is a `MirrorAnswerRefused` with the mirror's
 * codes; its message names "RPC endpoint" and never the address.
 *
 * An endpoint can echo the address it was asked at, in an error body or in a
 * JSON-RPC error's message, and ethers carries that text into the error it
 * builds. So the address's own parts (`rpcUrlSecrets`) are replaced in the
 * answer before ethers reads it, by exact match, as `redactRpcError` does
 * for an HTTP error's body; a relay's JSON still parses.
 */
export function createGuardedRpcSend(options: GuardedRpcSendOptions = {}): FetchGetUrlFunc {
  const maxBytes = options.maxBytes ?? MIRROR_ANSWER_MAX_BYTES;
  return async (req, signal) => {
    if (signal?.cancelled) throw makeError("request cancelled before sending", "CANCELLED");
    const fetchImpl = options.fetchImpl ?? fetch;
    const secrets = rpcUrlSecrets(req.url);
    const url = new URL(req.url);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw makeError(`unsupported protocol ${url.protocol.replace(/:$/, "")}`, "UNSUPPORTED_OPERATION", { operation: "request" });
    }
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(req.headers)) {
      const lower = name.toLowerCase();
      // The runtime sets the length itself and asks for, and undoes, compression itself.
      if (lower === "content-length" || lower === "accept-encoding") continue;
      headers[lower] = value;
    }
    if (url.username !== "" || url.password !== "") {
      if (headers.authorization === undefined) headers.authorization = basicAuthorization(url.username, url.password);
      url.username = "";
      url.password = "";
    }
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, req.timeout);
    let cancelled = false;
    signal?.addListener(() => {
      cancelled = true;
      controller.abort();
    });
    try {
      const body = req.body;
      const response = await fetchImpl(url.toString(), {
        method: req.method,
        headers,
        ...(body ? { body: body as unknown as BodyInit } : {}),
        redirect: "manual",
        signal: controller.signal,
      });
      if (isMirrorRedirect(response)) {
        await response.body?.cancel?.().catch(() => undefined);
        throw rpcRefusal.redirect();
      }
      let text: string;
      try {
        text = await readMirrorText(response, maxBytes);
      } catch (error) {
        // The shared read names a mirror; this source is an RPC endpoint.
        if (mirrorRefusalOf(error) === "too-large") throw rpcRefusal.tooLarge(maxBytes);
        throw error;
      }
      const answered: Record<string, string> = {};
      response.headers.forEach((value, name) => {
        answered[name.toLowerCase()] = value;
      });
      return { statusCode: response.status, statusMessage: response.statusText, headers: answered, body: new TextEncoder().encode(replaceRpcSecrets(text, secrets)) };
    } catch (error) {
      if (mirrorRefusalOf(error)) throw error;
      if (cancelled) throw makeError("request cancelled", "CANCELLED");
      if (timedOut) throw makeError("request timeout", "TIMEOUT", { operation: "request.send", reason: "timeout" } as never);
      throw error;
    } finally {
      clearTimeout(timer);
    }
  };
}

/** `retry-after` as ethers reads it: a whole number of milliseconds, or null when it would not use the header. */
function retryAfterMs(value: string | undefined): number | null {
  return typeof value === "string" && /^[1-9][0-9]*$/.test(value) ? Number.parseInt(value, 10) : null;
}

/**
 * Prepares a reader's request: the guarded sender in place of ethers' own,
 * and ethers' retry of a 429 held to `RPC_READER_MAX_TRIES` tries. ethers
 * reads `retry-after` as milliseconds and waits that long; a value over the
 * request's timeout ends the request with the 429 instead of being waited out.
 */
export function holdRpcRequest(request: FetchRequest, options: GuardedRpcSendOptions = {}): void {
  request.getUrlFunc = createGuardedRpcSend(options);
  request.retryFunc = async (req, response, attempt) => {
    if (attempt >= RPC_READER_MAX_TRIES - 1) return false;
    const wait = retryAfterMs(response.headers["retry-after"]);
    return wait === null || wait <= req.timeout;
  };
}
