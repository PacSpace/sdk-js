import { HttpClient } from '../client';
import type { RequestOptions } from '../types/config';

export type CustomerSharingState = 'ACTIVE' | 'OFF' | 'INHERIT';
export type CustomerEventCadence = 'PER_EVENT' | 'BATCHED';

export interface CreateCustomerOptions extends RequestOptions {
  displayName: string;
  customerId?: string;
  sharingStateHint?: CustomerSharingState;
  eventCadence?: CustomerEventCadence;
  unitLabel?: string;
}

export interface CreateCustomerResponse {
  customerId: string;
  displayName: string;
  source: 'manual';
  createdAt: string;
  route: string;
  sharingState: CustomerSharingState;
  eventCadence: CustomerEventCadence;
  unitLabel: string;
}

export class CustomersResource {
  constructor(private readonly client: HttpClient) {}

  /**
   * Create a dashboard customer before integration events arrive.
   *
   * This helper calls the JWT-authenticated dashboard API. Pass a dashboard JWT
   * using `dashboardToken`; Balance API keys alone cannot create customers.
   */
  async create(options: CreateCustomerOptions): Promise<CreateCustomerResponse> {
    const {
      displayName,
      customerId,
      sharingStateHint,
      eventCadence,
      unitLabel,
      ...requestOptions
    } = options;
    return this.client.post<CreateCustomerResponse>(
      '/dashboard/customers',
      {
        displayName,
        customerId,
        sharingStateHint,
        eventCadence,
        unitLabel,
      },
      requestOptions,
    );
  }
}
