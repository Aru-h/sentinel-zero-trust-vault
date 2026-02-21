import { Classification, Document, Role } from './types';

/**
 * SECURITY: API_URL is now read from the VITE_API_URL environment variable.
 * Set it in a .env.local file for dev, and in your deployment config for production.
 * Never hardcode a localhost fallback in code that ships to production.
 *
 * .env.local example:
 *   VITE_API_URL=http://localhost:5001
 *
 * .env.production example:
 *   VITE_API_URL=https://api.yoursentineldomain.com
 */
export const API_URL: string = import.meta.env.VITE_API_URL ?? 'http://localhost:5001';

/**
 * SECURITY: MOCK_USERS has been removed entirely.
 *
 * The previous version shipped a complete list of all valid usernames,
 * user IDs, roles, and an adversarial "Eve Hacker" test account inside
 * the compiled JavaScript bundle. Any visitor to the site could open
 * DevTools → Sources and extract a ready-made username list for
 * credential stuffing or targeted attacks.
 *
 * User data is now obtained exclusively from the backend /api/me endpoint
 * after authentication. No user enumeration data lives on the client.
 */

export const MOCK_DOCUMENTS: Document[] = [
  { id: 'd1',  title: 'Company Handbook',             classification: Classification.PUBLIC,       department: 'General',     locked: false },
  { id: 'd2',  title: 'Q3 Financial Report',          classification: Classification.CONFIDENTIAL, department: Role.FINANCE,   locked: true  },
  { id: 'd3',  title: 'Employee Salaries',            classification: Classification.RESTRICTED,   department: Role.HR,        locked: true  },
  { id: 'd4',  title: 'Project Sentinel Source Code', classification: Classification.INTERNAL,     department: Role.DEVELOPER, locked: true  },
  { id: 'd5',  title: 'Admin Credentials Backup',     classification: Classification.RESTRICTED,   department: Role.ADMIN,     locked: true  },
  { id: 'd6',  title: 'Office Floor Plan',            classification: Classification.INTERNAL,     department: 'General',     locked: true  },
  { id: 'd7',  title: 'Merger Strategy 2025',         classification: Classification.RESTRICTED,   department: Role.FINANCE,   locked: true  },
  { id: 'd8',  title: 'API Documentation',            classification: Classification.PUBLIC,       department: Role.DEVELOPER, locked: false },
  { id: 'd9',  title: 'Termination Policy',           classification: Classification.CONFIDENTIAL, department: Role.HR,        locked: true  },
  { id: 'd10', title: 'Audit Logs 2024',              classification: Classification.CONFIDENTIAL, department: Role.ADMIN,     locked: true  },
];

// Threat detection thresholds (used for UI-side display only; backend enforces independently)
export const THREAT_THRESHOLD_COUNT = 3;
export const THREAT_WINDOW_MS = 60_000; // 1 minute
