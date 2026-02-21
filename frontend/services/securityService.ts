/**
 * securityService.ts — CLIENT-SIDE UI STATE ONLY
 *
 * IMPORTANT: This service does NOT enforce access control.
 * All policy decisions are made exclusively by the backend (/api/access).
 *
 * This file is a thin UI helper. It exists only to manage the
 * in-memory log/alert state that is reflected in the dashboard.
 *
 * The previous version contained a full duplicate of the backend
 * policy engine (SecurityEngine.checkAccess). That code was removed
 * because:
 *   1. It compiled into the client bundle, revealing policy logic to attackers.
 *   2. It could give developers false confidence that access is enforced client-side.
 *   3. It was dead code — the backend already re-enforces everything.
 */

import { AccessLog, ThreatAlert } from '../types';

let _logs: AccessLog[]     = [];
let _alerts: ThreatAlert[] = [];

export const UISecurityState = {
  appendLog(log: AccessLog): void {
    _logs = [log, ..._logs];
  },

  appendAlert(alert: ThreatAlert): void {
    const now = Date.now();
    const duplicate = _alerts.some(
      a => a.userId === alert.userId && now - a.timestamp < 60_000
    );
    if (!duplicate) _alerts = [alert, ..._alerts];
  },

  getLogs():   AccessLog[]    { return _logs; },
  getAlerts(): ThreatAlert[]  { return _alerts; },

  clear(): void {
    _logs   = [];
    _alerts = [];
  },
};
