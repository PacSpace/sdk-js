import { createHmac, timingSafeEqual } from 'crypto';
import { WebhookVerificationError } from '../errors';
import type {
  WebhookEvent,
  WebhookHeaders,
} from './types';

/**
 * Options for webhook verification.
 */
export interface VerifyOptions {
  /**
   * Maximum age (seconds) of the timestamp before rejecting.
   * Protects against replay attacks.
   * @default 300 (5 minutes)
   */
  tolerance?: number;
}

/**
 * PacSpace Webhook verification and middleware.
 *
 * Provides HMAC-SHA256 signature verification for webhook payloads
 * using the algorithm documented at:
 * https://docs.pacspace.io/webhooks/signature-verification
 */
export class Webhooks {
  private readonly secret: string;

  /**
   * @param secret - Your webhook signing secret (from the PacSpace dashboard).
   */
  constructor(secret: string) {
    if (!secret) {
      throw new WebhookVerificationError(
        'Webhook secret is required. Get it from your PacSpace dashboard.',
      );
    }
    this.secret = secret;
  }

  /**
   * Verify a webhook payload and return the typed event.
   *
   * @param signature - The `X-PacSpace-Signature` header value.
   * @param timestamp - The `X-PacSpace-Timestamp` header value.
   * @param rawBody - The raw request body as a string (before JSON parsing).
   * @param options - Verification options (timestamp tolerance).
   * @returns The parsed and verified webhook event.
   * @throws WebhookVerificationError if verification fails.
   *
   * @example
   * ```typescript
   * const event = pac.webhooks.verify(
   *   req.headers['x-pacspace-signature'],
   *   req.headers['x-pacspace-timestamp'],
   *   req.rawBody,
   * );
   *
   * if (event.event === 'delta.verified') {
   *   console.log(event.data.receiptId);
   * }
   * ```
   */
  verify(
    signature: string,
    timestamp: string,
    rawBody: string,
    options?: VerifyOptions,
  ): WebhookEvent {
    if (!signature || !timestamp || !rawBody) {
      throw new WebhookVerificationError(
        'Missing required parameters: signature, timestamp, and rawBody are all required.',
      );
    }

    // Validate timestamp to prevent replay attacks
    this.validateTimestamp(timestamp, options?.tolerance ?? 300);

    // Reconstruct the signed content: "{timestamp}.{rawBody}"
    const signedContent = `${timestamp}.${rawBody}`;

    // Compute HMAC-SHA256
    const expected = Buffer.from(
      'v1=' +
        createHmac('sha256', this.secret).update(signedContent).digest('hex'),
    );

    // The header is one `v1=<hex>`, or, for 24 hours after a secret rotation
    // with overlap, two of them comma separated (the current secret's first,
    // then the previous secret's). The event is genuine when any one of them
    // matches this secret; each comparison is constant time.
    const matched = signature
      .split(',')
      .map((part) => part.trim())
      .filter((part) => part.startsWith('v1='))
      .some((candidate) => {
        const received = Buffer.from(candidate);
        return (
          received.length === expected.length &&
          timingSafeEqual(expected, received)
        );
      });

    if (!matched) {
      throw new WebhookVerificationError(
        'Signature mismatch. Ensure you are using the correct webhook secret and the raw (unparsed) request body.',
      );
    }

    // Parse and return the event
    try {
      return JSON.parse(rawBody) as WebhookEvent;
    } catch {
      throw new WebhookVerificationError(
        'Failed to parse webhook payload as JSON.',
      );
    }
  }

  /**
   * Verify using a headers object (convenience method).
   *
   * Extracts `x-pacspace-signature` and `x-pacspace-timestamp` from headers.
   *
   * @param headers - Headers object (Express req.headers or similar).
   * @param rawBody - The raw request body as a string.
   * @param options - Verification options.
   * @returns The parsed and verified webhook event.
   *
   * @example
   * ```typescript
   * const event = pac.webhooks.verifyFromHeaders(req.headers, req.rawBody);
   * ```
   */
  verifyFromHeaders(
    headers: WebhookHeaders | Record<string, string | string[] | undefined>,
    rawBody: string,
    options?: VerifyOptions,
  ): WebhookEvent {
    const signature = this.getHeader(headers, 'x-pacspace-signature');
    const timestamp = this.getHeader(headers, 'x-pacspace-timestamp');

    if (!signature) {
      throw new WebhookVerificationError(
        'Missing X-PacSpace-Signature header.',
      );
    }
    if (!timestamp) {
      throw new WebhookVerificationError(
        'Missing X-PacSpace-Timestamp header.',
      );
    }

    return this.verify(signature, timestamp, rawBody, options);
  }

  /**
   * Create an Express/Connect-compatible middleware for webhook verification.
   *
   * The middleware:
   * 1. Verifies the HMAC signature
   * 2. Validates the timestamp
   * 3. Attaches the parsed event to `req.pacspaceEvent`
   * 4. Calls `next()` on success, or responds with 401 on failure
   *
   * **Important:** Ensure raw body parsing is enabled before this middleware.
   *
   * @param options - Verification options.
   * @returns Express middleware function.
   *
   * @example
   * ```typescript
   * // Capture raw body (required for signature verification)
   * app.use('/webhooks', express.json({
   *   verify: (req, _res, buf) => { req.rawBody = buf.toString(); }
   * }));
   *
   * app.post('/webhooks/pacspace', pac.webhooks.middleware(), (req, res) => {
   *   const event = req.pacspaceEvent;
   *   console.log(`Received ${event.event}:`, event.data);
   *   res.status(200).json({ received: true });
   * });
   * ```
   */
  middleware(options?: VerifyOptions) {
    return (req: any, res: any, next: any) => {
      try {
        const rawBody = req.rawBody || JSON.stringify(req.body);
        const event = this.verifyFromHeaders(req.headers, rawBody, options);
        req.pacspaceEvent = event;
        next();
      } catch (err) {
        if (err instanceof WebhookVerificationError) {
          res.status(401).json({ error: err.message });
        } else {
          next(err);
        }
      }
    };
  }

  /**
   * Validate that the timestamp is within the tolerance window.
   */
  private validateTimestamp(timestamp: string, toleranceSeconds: number): void {
    const webhookTimeSeconds = this.parseTimestampToSeconds(timestamp);
    if (Number.isNaN(webhookTimeSeconds)) {
      throw new WebhookVerificationError(
        `Invalid timestamp: "${timestamp}". Expected Unix epoch in seconds or milliseconds.`,
      );
    }

    const currentTime = Math.floor(Date.now() / 1000);
    const age = Math.abs(currentTime - webhookTimeSeconds);

    if (age > toleranceSeconds) {
      throw new WebhookVerificationError(
        `Timestamp too old (${age}s > ${toleranceSeconds}s tolerance). This may be a replay attack, or your server clock is skewed.`,
      );
    }
  }

  /**
   * Convert epoch timestamp string to seconds.
   * Accepts both second and millisecond precision.
   */
  private parseTimestampToSeconds(timestamp: string): number {
    const raw = Number.parseInt(timestamp, 10);
    if (!Number.isFinite(raw)) {
      return Number.NaN;
    }
    // 13+ digits => milliseconds in current webhook workers.
    if (Math.abs(raw) >= 1_000_000_000_000) {
      return Math.floor(raw / 1000);
    }
    return raw;
  }

  /**
   * Extract a header value from a headers object (handles arrays).
   */
  private getHeader(
    headers: Record<string, string | string[] | undefined>,
    key: string,
  ): string | undefined {
    const value = headers[key] ?? headers[key.toLowerCase()];
    return Array.isArray(value) ? value[0] : value;
  }
}
