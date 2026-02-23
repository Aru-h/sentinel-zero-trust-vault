import { Classification, Document } from './types';

export const API_URL: string = '';

export const MOCK_DOCUMENTS: Document[] = [
  { id: 'd1',  title: 'Company Handbook',             classification: Classification.PUBLIC,       department: 'hr',      locked: false },
  { id: 'd2',  title: 'Q3 Financial Report',          classification: Classification.CONFIDENTIAL, department: 'finance', locked: true  },
  { id: 'd3',  title: 'Employee Salaries',            classification: Classification.RESTRICTED,   department: 'hr',      locked: true  },
  { id: 'd4',  title: 'Project Sentinel Source Code', classification: Classification.INTERNAL,     department: 'dev',     locked: true  },
  { id: 'd5',  title: 'Admin Credentials Backup',     classification: Classification.RESTRICTED,   department: 'admin',   locked: true  },
  { id: 'd6',  title: 'Office Floor Plan',            classification: Classification.INTERNAL,     department: 'hr',      locked: true  },
  { id: 'd7',  title: 'Merger Strategy 2025',         classification: Classification.RESTRICTED,   department: 'finance', locked: true  },
  { id: 'd8',  title: 'API Documentation',            classification: Classification.PUBLIC,       department: 'dev',     locked: false },
  { id: 'd9',  title: 'Termination Policy',           classification: Classification.CONFIDENTIAL, department: 'hr',      locked: true  },
  { id: 'd10', title: 'Audit Logs 2024',              classification: Classification.CONFIDENTIAL, department: 'admin',   locked: true  },
];
