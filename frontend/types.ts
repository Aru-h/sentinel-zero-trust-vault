export enum Role {
  ADMIN = 'Admin',
  HR = 'HR',
  DEVELOPER = 'Developer',
  FINANCE = 'Finance',
}

export enum Classification {
  PUBLIC = 'Public',
  INTERNAL = 'Internal',
  CONFIDENTIAL = 'Confidential',
  RESTRICTED = 'Restricted',
}

export enum AccessResult {
  ALLOWED = 'ALLOWED',
  DENIED = 'DENIED',
  TERMINATION_PENDING = 'TERMINATION_PENDING',
  SESSION_TERMINATED = 'SESSION_TERMINATED',
}

export interface User {
  id: string;
  name: string;
  role: Role;
  avatar: string;
}

export interface Document {
  id: string;
  title: string;
  classification: Classification;
  department: Role | 'General'; // Which department owns it
  content?: string; // Loaded on demand
  locked: boolean;
}

export interface AccessLog {
  id: string;
  timestamp: number;
  userId: string;
  userName: string;
  userRole: Role;
  documentId: string;
  documentTitle: string;
  result: AccessResult;
  reason: string;
}

export interface ThreatAlert {
  id: string;
  timestamp: number;
  userId: string;
  userName: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
}

export interface SecurityStats {
  totalRequests: number;
  deniedRequests: number;
  activeThreats: number;
  lastScan: string;
}
