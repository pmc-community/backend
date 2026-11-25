export interface AuditError {
    name: string;
    message: string;
    status?: number;
    code?: string;
    details?: unknown;
}


export type Variables = {
    client: {
        id: string;
        scopes: string[];
    };

    auditError?: AuditError;
};

export const authFailures = new Map<
  string,
  {
    count: number;
    reset: number;
  }
>();


//--------------------------------
// HEADER ANOMALIES
//--------------------------------
export type HeaderAnomalyType =
    | 'unexpected_header'
    | 'suspicious_header'
    | 'oversized_header'
    | 'invalid_header_value'
    | 'conflicting_headers'
    | 'duplicate_header_value'
    | 'header_volume'
    | 'method_override';

export interface HeaderAnomalyOptions {
    expectedHeaders: Set<string>;
    suspiciousHeaders: Set<string>;
    maxHeaderValueLength: number;
    maxTotalHeaderBytes: number;
}

export interface HeaderAnomaly {
    type: HeaderAnomalyType;
    header?: string;
    relatedHeaders?: string[];
    message: string;
    valueLength?: number;
    severity: 'low' | 'medium' | 'high';
}

//--------------------------------
// AUDIT LOG EVENT
//--------------------------------
export interface AuditLogEvent {
    server: string | null;
    serverIPs: string[];
    type: 'audit';
    timestamp: string;
    requestId: string;
    method: string;
    path: string;
    status: number;
    durationMs: number;
    clientId: string | null;
    ip: string | null;
    userAgent: string | null;
    headers: Record<string, string>;
    headerAnomalies: HeaderAnomaly[];
    outcome: 'success' | 'failure';
    slow: boolean;
    error: AuditError | null;
}
