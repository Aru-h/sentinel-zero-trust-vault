export enum Role {
  ADMIN = 'Admin',
  HR = 'HR',
  DEVELOPER = 'Developer',
  FINANCE = 'Finance',
}

export type RoleTitle = 'admin' | 'head' | 'employee' | 'intern';
export type Department = 'admin' | 'hr' | 'finance' | 'dev';

export enum Classification {
  PUBLIC = 'Public',
  INTERNAL = 'Internal',
  CONFIDENTIAL = 'Confidential',
  RESTRICTED = 'Restricted',
}

export enum AccessResult {
  ALLOWED = 'ALLOWED',
  DENIED = 'DENIED',
}

export interface User {
  id: string;
  name: string;
  role: Role;
  role_title: RoleTitle;
  department: Department;
  clearance_level: number;
  avatar: string;
}

export interface Document {
  id: string;
  title: string;
  classification: Classification;
  department: Department;
  required_clearance?: number;
  content?: string;
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
