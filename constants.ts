import { Classification, Document, Role } from './types';

// Backend URL — set via VITE_API_URL environment variable in Render dashboard
// Local dev: create a .env.local with VITE_API_URL=http://localhost:5001
export const API_URL: string = import.meta.env.VITE_API_URL ?? 'http://localhost:5001';

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

export const THREAT_THRESHOLD_COUNT = 3;
export const THREAT_WINDOW_MS = 60_000;
