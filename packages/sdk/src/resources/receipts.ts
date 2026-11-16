import type { HttpClient } from '../client';
import { mapApiError } from '../errors';
import type {
  CreateReceiptGrantParams,
  CreateReceiptGrantResponse,
  ReceiptAccessGrant,
  ReceiptDocument,
  ReceiptGetOptions,
  ReceiptListItem,
  ReceiptListOptions,
} from '../types/balance';
import type { RequestOptions } from '../types/config';

export class ReceiptsResource {
  constructor(private readonly client: HttpClient) {}

  async get(
    receiptId: string,
    options?: ReceiptGetOptions,
  ): Promise<ReceiptDocument> {
    const {
      customerDisplayName,
      locale,
      timezone,
      unit,
      ...requestOptions
    } = options ?? {};

    const params = new URLSearchParams();
    if (customerDisplayName !== undefined) {
      params.set('customerDisplayName', String(customerDisplayName));
    }
    if (locale !== undefined) {
      params.set('locale', locale);
    }
    if (timezone !== undefined) {
      params.set('timezone', timezone);
    }
    if (unit !== undefined) {
      params.set('unit', unit);
    }

    const query = params.toString();
    const path = `/api/v1/balance/receipts/${encodeURIComponent(receiptId)}${query ? `?${query}` : ''}`;

    return this.client.get<ReceiptDocument>(
      path,
      this.hasRequestOptions(requestOptions) ? requestOptions : undefined,
    );
  }

  async list(
    customerId: string,
    options?: ReceiptListOptions,
  ): Promise<ReceiptListItem[]> {
    const { limit, ...requestOptions } = options ?? {};

    const params = new URLSearchParams();
    if (limit !== undefined) {
      params.set('limit', String(limit));
    }

    const query = params.toString();
    const path = `/api/v1/balance/customers/${encodeURIComponent(customerId)}/receipts${query ? `?${query}` : ''}`;
    const response = await this.client.get<{ receipts?: ReceiptListItem[] }>(
      path,
      this.hasRequestOptions(requestOptions) ? requestOptions : undefined,
    );
    return Array.isArray(response.receipts) ? response.receipts : [];
  }

  async preview(options?: RequestOptions): Promise<ReceiptDocument> {
    return this.client.get<ReceiptDocument>(
      '/api/v1/balance/receipts/preview',
      options,
    );
  }

  fromUrl(receiptUrl: string): string {
    let pathname = receiptUrl;
    try {
      pathname = new URL(receiptUrl).pathname;
    } catch {
      // allow relative paths
    }

    const match = pathname.match(/\/receipt\/([^/?#]+)/i);
    const value = match?.[1]?.replace(/\.pdf$/i, '')?.trim();
    if (!value) {
      throw new Error('Could not parse receiptId from URL');
    }
    return decodeURIComponent(value);
  }

  async downloadPdf(receiptId: string): Promise<ArrayBuffer> {
    const url = `${this.client.getBaseUrl()}/api/v1/receipt/${encodeURIComponent(receiptId)}.pdf`;
    const response = await fetch(url, { method: 'GET' });

    if (!response.ok) {
      const errorBody = (await response.json().catch(() => null)) as
        | Record<string, unknown>
        | null;
      const message =
        typeof errorBody?.message === 'string'
          ? errorBody.message
          : typeof errorBody?.error === 'string'
            ? errorBody.error
            : response.statusText;
      throw mapApiError(
        response.status,
        message,
        `/api/v1/receipt/${encodeURIComponent(receiptId)}.pdf`,
        response.headers,
        {
          code:
            typeof errorBody?.code === 'string'
              ? errorBody.code
              : undefined,
        },
      );
    }

    return response.arrayBuffer();
  }

  /**
   * Issue a receipt access grant — a separately revocable, optionally
   * expiring authorization for receipt retrieval.
   *
   * The returned token is shown once and never stored; share `grantUrl`
   * with the counterparty. Revoke the grant at any time to cut off later
   * retrieval.
   *
   * @example
   * ```typescript
   * const { grantUrl } = await pac.balance.receipts.createGrant('chk_abc123', {
   *   kind: 'RECIPIENT_BOUND',
   *   recipientEmail: 'auditor@counterparty.com',
   *   ttlHours: 24 * 30,
   *   label: 'Q3 audit',
   * });
   * ```
   */
  async createGrant(
    receiptId: string,
    params: CreateReceiptGrantParams,
    options?: RequestOptions,
  ): Promise<CreateReceiptGrantResponse> {
    return this.client.post<CreateReceiptGrantResponse>(
      `/api/v1/balance/receipt/${encodeURIComponent(receiptId)}/grants`,
      params,
      options,
    );
  }

  /**
   * List access grants for a receipt, including a read-only entry for
   * Shared Record step-up when the receipt is protected by a customer link.
   */
  async listGrants(
    receiptId: string,
    options?: RequestOptions,
  ): Promise<ReceiptAccessGrant[]> {
    const response = await this.client.get<{ grants?: ReceiptAccessGrant[] }>(
      `/api/v1/balance/receipt/${encodeURIComponent(receiptId)}/grants`,
      options,
    );
    return Array.isArray(response.grants) ? response.grants : [];
  }

  /**
   * Revoke a grant so later retrieval with its token fails. Revocation
   * cannot recall a receipt document a party has already downloaded.
   */
  async revokeGrant(
    receiptId: string,
    grantId: string,
    params?: { reason?: string },
    options?: RequestOptions,
  ): Promise<ReceiptAccessGrant> {
    const response = await this.client.post<{ grant: ReceiptAccessGrant }>(
      `/api/v1/balance/receipt/${encodeURIComponent(receiptId)}/grants/${encodeURIComponent(grantId)}/revoke`,
      params ?? {},
      options,
    );
    return response.grant;
  }

  emailBody(receipt: ReceiptDocument): string {
    const closingBalance = new Intl.NumberFormat(receipt.locale, {
      minimumFractionDigits: 0,
      maximumFractionDigits: 2,
    }).format(receipt.summary.closingBalance);

    return [
      'Your receipt is ready.',
      '',
      `Receipt ID: ${receipt.receiptId}`,
      `Period: ${receipt.period.label}`,
      `Closing balance: ${closingBalance} ${receipt.unit}`,
      `View online: ${receipt.links.permalink}`,
      '',
      'If this does not look right, open the dispute link in the receipt footer.',
    ].join('\n');
  }

  private hasRequestOptions(options: Record<string, unknown>): boolean {
    return Object.keys(options).length > 0;
  }
}
