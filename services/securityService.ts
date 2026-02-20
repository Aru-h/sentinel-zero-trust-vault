import { User, Document, AccessResult, AccessLog, ThreatAlert, Role, Classification } from '../types';
import { THREAT_THRESHOLD_COUNT, THREAT_WINDOW_MS } from '../constants';
import { v4 as uuidv4 } from 'uuid';

// In-memory store for simulation
let logs: AccessLog[] = [];
let alerts: ThreatAlert[] = [];

export const SecurityEngine = {
  
  checkAccess: (user: User, doc: Document): { result: AccessResult; reason: string } => {
    // 1. Public documents are accessible by everyone
    if (doc.classification === Classification.PUBLIC) {
      return { result: AccessResult.ALLOWED, reason: 'Public Classification' };
    }

    // 2. Admins have override access to everything EXCEPT strict separation of duties (optional, but let's say Admin can see all for this demo)
    if (user.role === Role.ADMIN) {
      return { result: AccessResult.ALLOWED, reason: 'Admin Override' };
    }

    // 3. Department matching for Confidential/Restricted
    const isSameDepartment = doc.department === 'General' || doc.department === user.role;

    if (doc.classification === Classification.INTERNAL) {
        // Internal docs: Any authenticated user can view (in this zero trust model, "authenticated" is assumed if they are in the system, but let's enforce dept check for stricter zero trust if desired. Standard ZT: Least Privilege).
        // Let's say Internal is open to all employees.
        return { result: AccessResult.ALLOWED, reason: 'Internal Access Policy' };
    }

    if (doc.classification === Classification.CONFIDENTIAL) {
      if (isSameDepartment) {
        return { result: AccessResult.ALLOWED, reason: 'Role-Based Access (Department Match)' };
      }
      return { result: AccessResult.DENIED, reason: 'Department Mismatch' };
    }

    if (doc.classification === Classification.RESTRICTED) {
      // Restricted requires explicit check even if same department (Simulation: Random MFA failure or stricter role check)
      if (isSameDepartment) {
         // In a real app, we'd check an Access Control List (ACL).
         // For this hackathon demo: Only Admin can view Restricted, OR the specific Department Head. 
         // Let's assume standard users cannot view Restricted even in their own department without escalation.
         return { result: AccessResult.DENIED, reason: 'Restricted: Escalation Required' };
      }
      return { result: AccessResult.DENIED, reason: 'Restricted: Unauthorized' };
    }

    return { result: AccessResult.DENIED, reason: 'Implicit Deny' };
  },

  logAccess: (user: User, doc: Document, result: AccessResult, reason: string): AccessLog => {
    const log: AccessLog = {
      id: uuidv4(),
      timestamp: Date.now(),
      userId: user.id,
      userName: user.name,
      userRole: user.role,
      documentId: doc.id,
      documentTitle: doc.title,
      result,
      reason,
    };
    logs = [log, ...logs]; // Prepend
    return log;
  },

  detectInsiderThreat: (user: User): ThreatAlert | null => {
    const now = Date.now();
    // Filter logs for this user, denied, within the window
    const recentDenials = logs.filter(
      l => l.userId === user.id && 
      l.result === AccessResult.DENIED && 
      (now - l.timestamp) < THREAT_WINDOW_MS
    );

    if (recentDenials.length >= THREAT_THRESHOLD_COUNT) {
      const alert: ThreatAlert = {
        id: uuidv4(),
        timestamp: now,
        userId: user.id,
        userName: user.name,
        severity: recentDenials.length > 5 ? 'CRITICAL' : 'HIGH',
        description: `Multiple denied access attempts (${recentDenials.length}) detected within 1 minute. Possible lateral movement or credential compromise.`,
      };
      // Check if we recently alerted for this to avoid spamming (simple debounce)
      const existingRecentAlert = alerts.find(a => a.userId === user.id && (now - a.timestamp) < THREAT_WINDOW_MS);
      if (!existingRecentAlert) {
        alerts = [alert, ...alerts];
        return alert;
      }
    }
    return null;
  },

  getLogs: () => logs,
  getAlerts: () => alerts,
  clearLogs: () => { logs = []; alerts = []; }
};