import {
  FetchRequest,
  JsonRpcProvider,
  WebSocketProvider,
  makeError,
  type ErrorCode,
  type JsonRpcApiProviderOptions,
  type JsonRpcPayload,
  type JsonRpcResult,
  type Networkish,
} from "ethers";

/**
 * RPC URLs carry the provider's access token in the path, the query or the
 * userinfo. ethers puts the whole request URL in an HTTP error's message and
 * the request itself on the error, and `ws` names the URL when it refuses
 * one. Providers built here throw errors that keep ethers' code, its short
 * message and the answer's status and body, with this provider's own URL
 * parts replaced, and nothing else; a socket's errors reach the caller's
 * handler as the endpoint's host and a message.
 */

export const RPC_URL_REDACTED = "[redacted]";

/** Shorter pieces (`v2`, `api`, `rpc`) are route names; replacing them would corrupt a response body. */
const MIN_SECRET_LENGTH = 8;
const URL_IN_TEXT = /[a-z][a-z0-9+.-]*:\/\/[^\s"'<>\\`]+/gi;
const RAW_SEPARATORS = /[/?&=#;@:]/;
const ETHERS_ERROR_EXTRA_FIELDS = ["operation", "reason", "event"] as const;

function normalizeRpcUrl(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith("wss://")) return trimmed.replace(/^wss:\/\//, "https://");
  if (trimmed.startsWith("ws://")) return trimmed.replace(/^ws:\/\//, "http://");
  return trimmed;
}

/** The endpoint's host, the only part of an RPC URL that may be written to a log line or a stored row. */
export function rpcEndpointLabel(value: string): string {
  try {
    return new URL(normalizeRpcUrl(value)).hostname.toLowerCase();
  } catch {
    return "unparseable-rpc-endpoint";
  }
}

function addSecret(found: Set<string>, value: string, minLength: number): void {
  if (value.length < minLength) return;
  found.add(value);
  try {
    const decoded = decodeURIComponent(value);
    if (decoded.length >= minLength) found.add(decoded);
  } catch {
    // A malformed escape is kept as written.
  }
}

/**
 * Every piece of `url` that could be a credential: path segments, query keys
 * and values, userinfo, each raw and decoded, of at least `minLength`
 * characters, longest first. An unparseable value is a secret whole.
 */
export function rpcUrlSecrets(url: string, minLength = MIN_SECRET_LENGTH): string[] {
  const found = new Set<string>();
  const trimmed = url.trim();
  const add = (value: string) => addSecret(found, value, minLength);
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    add(trimmed);
    return [...found];
  }
  for (const segment of parsed.pathname.split("/")) add(segment);
  for (const part of parsed.search.replace(/^\?/, "").split("&")) {
    for (const piece of part.split("=")) add(piece);
  }
  add(parsed.username);
  add(parsed.password);
  const afterScheme = trimmed.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
  const authorityEnd = afterScheme.search(/[/?#]/);
  const authority = authorityEnd < 0 ? afterScheme : afterScheme.slice(0, authorityEnd);
  const at = authority.lastIndexOf("@");
  if (at >= 0) for (const piece of authority.slice(0, at).split(":")) add(piece);
  const rest = authorityEnd < 0 ? "" : afterScheme.slice(authorityEnd);
  for (const piece of rest.split(RAW_SEPARATORS)) add(piece);
  return [...found].sort((a, b) => b.length - a.length);
}

/** `text` with each of `secrets` replaced, by exact match; never a pattern built from a value. */
export function replaceRpcSecrets(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const secret of secrets) {
    if (secret.length > 0 && out.includes(secret)) out = out.split(secret).join(RPC_URL_REDACTED);
  }
  return out;
}

function reduceUrls(text: string): string {
  return text.replace(URL_IN_TEXT, (url) => `[rpc-url host=${rpcEndpointLabel(url)}]`);
}

function cleanText(text: string, secrets: readonly string[]): string {
  return reduceUrls(replaceRpcSecrets(text, secrets));
}

type EthersErrorShape = {
  code: string;
  shortMessage: string;
  info?: unknown;
} & Partial<Record<(typeof ETHERS_ERROR_EXTRA_FIELDS)[number], unknown>>;

function isEthersError(error: unknown): error is EthersErrorShape {
  if (error === null || typeof error !== "object") return false;
  const candidate = error as Record<string, unknown>;
  return typeof candidate.code === "string" && typeof candidate.shortMessage === "string";
}

/** Structural, since an error made in another realm (a Node system error under Jest's VM) is not `instanceof Error`. */
function isErrorLike(error: unknown): error is Error {
  return error !== null && typeof error === "object" && typeof (error as { message?: unknown }).message === "string";
}

function holdsSecret(text: string, secrets: readonly string[]): boolean {
  return secrets.some((secret) => secret.length > 0 && text.includes(secret));
}

/** Stack frames are `file://` URLs under ESM, so only the message is searched for URLs. */
function exposesEndpoint(error: Error, secrets: readonly string[]): boolean {
  URL_IN_TEXT.lastIndex = 0;
  return URL_IN_TEXT.test(error.message) || holdsSecret(error.message, secrets) || holdsSecret(error.stack ?? "", secrets);
}

/**
 * The error a redacting provider throws in place of `error`. An ethers error
 * becomes a new one with the same code, its short message, its `operation`,
 * `reason` and `event`, and its `info` less `requestUrl`: `responseStatus`
 * and `responseBody` stay, the body with only `secrets` replaced so a relay's
 * JSON answer still parses. The request, the response and any nested error
 * are dropped. Any other error is returned as it is unless its message or
 * stack holds a URL or a secret, when it is rebuilt with its name and code.
 */
export function redactRpcError(error: unknown, secrets: readonly string[]): Error {
  if (isEthersError(error)) {
    const info: Record<string, unknown> = {};
    const source = error.info !== null && typeof error.info === "object" ? (error.info as Record<string, unknown>) : {};
    for (const [key, value] of Object.entries(source)) {
      if (key === "requestUrl") continue;
      if (key === "responseBody") {
        if (typeof value === "string") info.responseBody = replaceRpcSecrets(value, secrets);
        continue;
      }
      if (typeof value === "string") info[key] = cleanText(value, secrets);
      else if (typeof value === "number" || typeof value === "boolean" || value === null) info[key] = value;
    }
    const extra: Record<string, string> = {};
    for (const field of ETHERS_ERROR_EXTRA_FIELDS) {
      const value = error[field];
      if (typeof value === "string") extra[field] = cleanText(value, secrets);
    }
    const details = Object.keys(info).length > 0 ? { ...extra, info } : extra;
    return makeError(cleanText(error.shortMessage, secrets), error.code as ErrorCode, details as never);
  }
  if (isErrorLike(error)) {
    if (!exposesEndpoint(error, secrets)) return error;
    const rebuilt = new Error(cleanText(error.message, secrets));
    if (typeof error.name === "string") rebuilt.name = error.name;
    const code = (error as { code?: unknown }).code;
    if (typeof code === "string") Object.defineProperty(rebuilt, "code", { value: code, enumerable: true });
    return rebuilt;
  }
  return new Error(cleanText(String(error), secrets));
}

export type RpcProviderOptions = JsonRpcApiProviderOptions & {
  /** The HTTP request timeout in milliseconds (ethers' `FetchRequest.timeout`, 300 s by default). */
  timeoutMs?: number;
};

class RedactingJsonRpcProvider extends JsonRpcProvider {
  readonly #secrets: readonly string[];

  constructor(url: string, network: Networkish | undefined, options: RpcProviderOptions) {
    const { timeoutMs, ...providerOptions } = options;
    const request = new FetchRequest(url);
    if (timeoutMs !== undefined) request.timeout = timeoutMs;
    super(request, network, providerOptions);
    this.#secrets = rpcUrlSecrets(url);
  }

  override async _send(payload: JsonRpcPayload | Array<JsonRpcPayload>): Promise<Array<JsonRpcResult>> {
    try {
      return await super._send(payload);
    } catch (error) {
      throw redactRpcError(error, this.#secrets);
    }
  }
}

/** A JSON-RPC provider over HTTP whose errors never carry `url`'s path, query or userinfo. */
export function createRpcProvider(url: string, network?: Networkish, options: RpcProviderOptions = {}): JsonRpcProvider {
  return new RedactingJsonRpcProvider(url, network, options);
}

/** `host` is the endpoint's label (`rpcEndpointLabel`), never its URL. */
export type RpcSocketFailure = { host: string; message: string };

function socketEventMessage(event: unknown): string {
  if (event !== null && typeof event === "object") {
    const candidate = event as { message?: unknown; error?: { message?: unknown } };
    if (typeof candidate.message === "string" && candidate.message !== "") return candidate.message;
    if (typeof candidate.error?.message === "string") return candidate.error.message;
  }
  return "socket error";
}

/**
 * A JSON-RPC provider over a WebSocket. Construction errors are rethrown
 * without `url`, and the socket gets its own error handler, which passes the
 * endpoint's host and the event's message, cleaned, to `onError`; so no
 * socket error goes unhandled and none reaches a log with the socket on it.
 */
export function createRpcSocketProvider(
  url: string,
  onError: (failure: RpcSocketFailure) => void,
  network?: Networkish,
  options?: JsonRpcApiProviderOptions,
): WebSocketProvider {
  const secrets = rpcUrlSecrets(url);
  const host = rpcEndpointLabel(url);
  let provider: WebSocketProvider;
  try {
    provider = new WebSocketProvider(url, network, options);
  } catch (error) {
    throw redactRpcError(error, secrets);
  }
  provider.websocket.onerror = (event: unknown) => {
    onError({ host, message: cleanText(socketEventMessage(event), secrets) });
  };
  return provider;
}
