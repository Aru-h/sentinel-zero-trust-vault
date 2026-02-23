import React, { useEffect, useState } from 'react';
import { AccessLog, ThreatAlert, User } from '../types';
import { API_URL } from '../constants';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend
} from 'recharts';

interface ThreatDashboardProps {
  logs: AccessLog[];
  alerts: ThreatAlert[];
  currentUser: User;
  authFetch: (url: string, options?: RequestInit) => Promise<Response>;
  onBlocked: () => Promise<void>;
  roleBreakdown?: Array<{ role_title: string; count: number }> ;
  clearanceDistribution?: Array<{ clearance_level: number; count: number }>;
  clearanceMismatchDenied?: number;
  onApprovalToken?: (documentId: string, token: string) => void;
}

interface LiveStatsResponse {
  allowed: number;
  denied: number;
  rejected: number;
}

interface AccessRequestItem {
  id: string;
  userId: string;
  userName: string;
  documentId: string;
  documentTitle: string;
  timestamp: number;
  status: 'PENDING' | 'APPROVED';
}

export const ThreatDashboard: React.FC<ThreatDashboardProps> = ({ logs, alerts, currentUser, authFetch, onBlocked, onApprovalToken }) => {
  const [analysis, setAnalysis] = useState('Initializing threat rule engine...');
  const [roleFilter, setRoleFilter] = useState<'All' | 'Developer' | 'HR' | 'Finance' | 'Admin'>('All');
  const [adminTab, setAdminTab] = useState<'events' | 'requests'>('events');
  const [liveStats, setLiveStats] = useState<LiveStatsResponse>({ allowed: 0, denied: 0, rejected: 0 });
  const [requests, setRequests] = useState<AccessRequestItem[]>([]);

  useEffect(() => {
    // Pure rule-based analysis — no external AI/API dependency
    const total   = logs.length;
    const denied  = logs.filter(l => l.result === 'DENIED').length;
    const rate    = total > 0 ? ((denied / total) * 100).toFixed(0) : '0';
    const flagged = alerts.length;

    if (flagged >= 5) {
      setAnalysis(
        `CRITICAL: ${flagged} active threat alerts. Denial rate ${rate}%. ` +
        `Immediate investigation and account suspension recommended.`
      );
    } else if (flagged >= 2) {
      setAnalysis(
        `WARNING: ${flagged} users flagged for repeated access denials. ` +
        `Denial rate ${rate}%. Review their recent activity.`
      );
    } else if (flagged === 1) {
      setAnalysis(`Suspicious activity on 1 account. Denial rate ${rate}%. Monitor closely.`);
    } else if (Number(rate) > 30 && total >= 5) {
      setAnalysis(`Elevated denial rate (${rate}%) across ${total} requests. Review access policies.`);
    } else {
      setAnalysis(`System operating normally. ${total} requests processed — ${denied} denied.`);
    }
  }, [logs, alerts]);

  const allowedCount = logs.filter(l => l.result === 'ALLOWED').length;
  const deniedCount  = logs.filter(l => l.result === 'DENIED').length;
  const filteredLogs = logs.filter((log) => roleFilter === 'All' || log.userRole === roleFilter);

  useEffect(() => {
    const fetchLiveStats = async () => {
      const res = await authFetch(`${API_URL}/api/admin/live-stats`);
      if (res.status === 403) {
        const data = await res.json();
        if (data?.error === 'User blocked by admin') {
          await onBlocked();
        }
        return;
      }
      if (!res.ok) return;
      const data: LiveStatsResponse = await res.json();
      setLiveStats(data);
    };

    fetchLiveStats();
    const timer = setInterval(fetchLiveStats, 1000);
    return () => clearInterval(timer);
  }, [authFetch, onBlocked]);

  useEffect(() => {
    const fetchRequests = async () => {
      const res = await authFetch(`${API_URL}/api/admin/requests`);
      if (res.status === 403) {
        const data = await res.json();
        if (data?.error === 'User blocked by admin') {
          await onBlocked();
        }
        return;
      }
      if (!res.ok) return;
      const data = await res.json();
      setRequests(data.requests ?? []);
    };

    if (adminTab === 'requests') {
      fetchRequests();
      const timer = setInterval(fetchRequests, 1000);
      return () => clearInterval(timer);
    }
  }, [adminTab, authFetch, onBlocked]);

  const handleApproveRequest = async (requestId: string, documentId: string) => {
    const res = await authFetch(`${API_URL}/api/admin/approve-request`, {
      method: 'POST',
      body: JSON.stringify({ requestId }),
    });
    if (res.status === 403) {
      const data = await res.json();
      if (data?.error === 'User blocked by admin') {
        await onBlocked();
      }
      return;
    }
    if (!res.ok) return;
    const data = await res.json().catch(() => ({}));
    const token = typeof data?.token === 'string' ? data.token : '';
    if (token && onApprovalToken) {
      onApprovalToken(documentId, token);
    }
    setRequests(prev => prev.filter(r => r.id !== requestId));
  };

  const handleBlockUser = async (userId: string) => {
    const res = await authFetch(`${API_URL}/api/admin/block-user`, {
      method: 'POST',
      body: JSON.stringify({ userId }),
    });
    if (!res.ok) return;
    setRequests(prev => prev.filter(r => r.userId !== userId));
  };

  const pieData = [
    { name: 'Allowed', value: allowedCount, color: '#10b981' },
    { name: 'Denied',  value: deniedCount,  color: '#ef4444' },
  ];

  const roleDataMap = logs.reduce((acc, log) => {
    if (!acc[log.userRole]) acc[log.userRole] = { role: log.userRole, allowed: 0, denied: 0 };
    if (log.result === 'ALLOWED') acc[log.userRole].allowed += 1;
    else acc[log.userRole].denied += 1;
    return acc;
  }, {} as Record<string, { role: string; allowed: number; denied: number }>);

  const barData = Object.values(roleDataMap);

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[
          { label: 'Allowed',          value: liveStats.allowed,  color: 'text-accent' },
          { label: 'Denied',           value: liveStats.denied,   color: 'text-danger' },
          { label: 'Rejected',         value: liveStats.rejected, color: 'text-warning' },
          { label: 'Active Threats',   value: alerts.length,      color: 'text-warning' },
        ].map(stat => (
          <div key={stat.label} className="bg-surface p-4 rounded-lg border border-gray-700">
            <h3 className="text-gray-400 text-xs font-mono uppercase">{stat.label}</h3>
            <p className={`text-2xl font-bold mt-1 ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Charts */}
        <div className="lg:col-span-2 bg-surface p-4 rounded-lg border border-gray-700 min-h-[300px]">
          <h3 className="text-gray-300 font-bold mb-4 flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
            Traffic Analysis
          </h3>
          <p className="text-xs text-gray-500 font-mono mb-3">Viewing as: {currentUser.name} ({currentUser.role})</p>
          <div className="h-64 w-full flex gap-4">
            <div className="flex-1">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="role" stroke="#9ca3af" fontSize={10} />
                  <YAxis stroke="#9ca3af" fontSize={10} />
                  <Tooltip contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#f3f4f6' }} cursor={{ fill: '#374151', opacity: 0.4 }} />
                  <Legend />
                  <Bar dataKey="allowed" stackId="a" fill="#10b981" name="Allowed" />
                  <Bar dataKey="denied"  stackId="a" fill="#ef4444" name="Denied"  />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="w-48">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={40} outerRadius={60} paddingAngle={5} dataKey="value">
                    {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Rule Engine Panel — replaces removed "SOC AI Analyst" */}
        <div className="bg-surface p-4 rounded-lg border border-gray-700 flex flex-col">
          <h3 className="text-gray-300 font-bold mb-4 flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Threat Rule Engine
          </h3>
          <div className="bg-black/30 p-4 rounded border border-gray-800 flex-1 text-sm text-gray-300 font-mono leading-relaxed">
            {analysis}
          </div>
          {alerts.length > 0 && (
            <div className="mt-4 space-y-2">
              <h4 className="text-xs text-danger font-bold uppercase">Flagged Accounts</h4>
              {alerts.slice(0, 5).map(a => (
                <div key={a.id} className="bg-danger/10 border border-danger/30 rounded p-2 text-xs">
                  <span className="font-bold text-danger">{a.userName}</span>
                  <span className="text-gray-400 ml-2">{a.description}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Log Table */}
      <div className="bg-surface rounded-lg border border-gray-700 overflow-hidden">
        <div className="p-4 border-b border-gray-700">
          <div className="flex items-center justify-between gap-3">
            <h3 className="text-gray-300 font-bold text-sm">Recent Access Events</h3>
            <div className="flex items-center gap-2">
              <button className={`px-3 py-1 rounded text-xs ${adminTab === 'events' ? 'bg-primary text-white' : 'bg-black/30 text-gray-300'}`} onClick={() => setAdminTab('events')}>Events</button>
              <button className={`px-3 py-1 rounded text-xs ${adminTab === 'requests' ? 'bg-primary text-white' : 'bg-black/30 text-gray-300'}`} onClick={() => setAdminTab('requests')}>Access Requests</button>
            </div>
          </div>
        </div>
        {adminTab === 'events' && (
        <>
        <div className="p-4 border-b border-gray-700">
          <select
            className="bg-black/30 border border-gray-700 rounded px-3 py-2 text-xs text-gray-200"
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value as 'All' | 'Developer' | 'HR' | 'Finance' | 'Admin')}
          >
            <option value="All">All</option>
            <option value="Developer">Developer</option>
            <option value="HR">HR</option>
            <option value="Finance">Finance</option>
            <option value="Admin">Admin</option>
          </select>
        </div>
        <div className="overflow-x-auto max-h-96 overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="bg-black/20">
              <tr>
                {['Time', 'User', 'Role', 'Document', 'Result', 'Reason', 'Actions'].map(h => (
                  <th key={h} className="text-left px-4 py-2 text-gray-500 font-mono uppercase">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredLogs.slice(0, 20).map(log => (
                <tr key={log.id} className="border-t border-gray-800 hover:bg-white/5">
                  <td className="px-4 py-2 text-gray-400">{new Date(log.timestamp).toLocaleTimeString()}</td>
                  <td className="px-4 py-2 text-white">{log.userName}</td>
                  <td className="px-4 py-2 text-gray-400">{log.userRole}</td>
                  <td className="px-4 py-2 text-gray-300">{log.documentTitle}</td>
                  <td className={`px-4 py-2 font-bold ${log.result === 'ALLOWED' ? 'text-accent' : 'text-danger'}`}>{log.result}</td>
                  <td className="px-4 py-2 text-gray-500">{log.reason}</td>
                  {currentUser.role === 'Admin' && (
                    <td className="px-4 py-2">
                      <button className="bg-danger/20 text-danger px-2 py-1 rounded" onClick={() => handleBlockUser(log.userId)}>Block User</button>
                    </td>
                  )}
                </tr>
              ))}
              {filteredLogs.length === 0 && (
                <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-600">No events yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
        </>
        )}

        {adminTab === 'requests' && (
          <div className="overflow-x-auto max-h-96 overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="bg-black/20">
                <tr>
                  {['User', 'Document', 'Timestamp', 'Status', 'Actions'].map(h => (
                    <th key={h} className="text-left px-4 py-2 text-gray-500 font-mono uppercase">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {requests.map((item) => (
                  <tr key={item.id} className="border-t border-gray-800 hover:bg-white/5">
                    <td className="px-4 py-2 text-white">{item.userName}</td>
                    <td className="px-4 py-2 text-gray-300">{item.documentTitle} ({item.documentId})</td>
                    <td className="px-4 py-2 text-gray-400">{new Date(item.timestamp * 1000).toLocaleString()}</td>
                    <td className="px-4 py-2 text-warning font-bold">{item.status}</td>
                    <td className="px-4 py-2"><button className="bg-primary text-white px-2 py-1 rounded" onClick={() => handleApproveRequest(item.id, item.documentId)}>Approve</button></td>
                  </tr>
                ))}
                {requests.length === 0 && (
                  <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-600">No pending requests.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
