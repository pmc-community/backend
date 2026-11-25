// ------------------------------------------------------------
// Logger
// ------------------------------------------------------------

import { AuditLogEvent } from '../types/types';
import { proxiedGlobals } from '../hooks/hooks';

proxiedGlobals.logEvent = (event: AuditLogEvent) => {
    console.log('[logEvent]', event);
    return event.requestId; // --> return relevant info if there is a hook after the execution
};
export const logEvent = proxiedGlobals.logEvent;

export function logSuspiciousRequest(event: any) {
    console.log(event);
}

export function logConcurrentRequests(event: any) {
    console.log(event);
}