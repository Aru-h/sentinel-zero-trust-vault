import React, { useEffect, useState } from 'react';
import { AccessLog, ThreatAlert, User } from '../types';
import {  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend } from 'recharts';

interface ThreatDashboardProps {
  logs: AccessLog[];
  alerts: ThreatAlert[];
  currentUser: User;
}

export const ThreatDashboard: React.FC<ThreatDashboardProps> = ({ logs, alerts, currentUser }) => {
  const [analysis, setAnalysis] = useState<string>("Initializing Threat Engine...");


  useEffect(() => {
  if (alerts.length >= 3) {
    setAnalysis("High threat activity detected. Multiple denied access attempts observed.");
  } else if (alerts.length > 0) {
    setAnalysis("Suspicious activity detected.");
  } else {
    setAnalysis("System operating normally.");
  }
}, [logs, alerts]);


  // Chart Data Preparation
  const allowedCount = logs.filter(l => l.result === 'ALLOWED').length;
  const deniedCount = logs.filter(l => l.result === 'DENIED').length;
  
  const pieData = [
    { name: 'Allowed', value: allowedCount, color: '#10b981' }, // Green
    { name: 'Denied', value: deniedCount, color: '#ef4444' },   // Red
  ];

  // Bar chart: Access by Role
  const roleDataMap = logs.reduce((acc, log) => {
    if (!acc[log.userRole]) acc[log.userRole] = { role: log.userRole, allowed: 0, denied: 0 };
    if (log.result === 'ALLOWED') acc[log.userRole].allowed += 1;
    else acc[log.userRole].denied += 1;
    return acc;
  }, {} as Record<string, { role: string; allowed: number; denied: number }>);

  const barData = Object.values(roleDataMap);

  return (
    <div className="space-y-6">
      {/* Top Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-surface p-4 rounded-lg border border-gray-700">
          <h3 className="text-gray-400 text-xs font-mono uppercase">Total Requests</h3>
          <p className="text-2xl font-bold text-white mt-1">{logs.length}</p>
        </div>
        <div className="bg-surface p-4 rounded-lg border border-gray-700">
          <h3 className="text-gray-400 text-xs font-mono uppercase">Denied</h3>
          <p className="text-2xl font-bold text-danger mt-1">{deniedCount}</p>
        </div>
        <div className="bg-surface p-4 rounded-lg border border-gray-700">
          <h3 className="text-gray-400 text-xs font-mono uppercase">Active Threats</h3>
          <p className="text-2xl font-bold text-warning mt-1">{alerts.length}</p>
        </div>
        <div className="bg-surface p-4 rounded-lg border border-gray-700">
           <h3 className="text-gray-400 text-xs font-mono uppercase">System Status</h3>
           <div className="flex items-center gap-2 mt-1">
             <div className={`w-3 h-3 rounded-full ${alerts.length > 0 ? 'bg-danger animate-pulse' : 'bg-accent'}`}></div>
             <p className="text-sm font-bold text-white">{alerts.length > 0 ? 'ELEVATED RISK' : 'SECURE'}</p>
           </div>
        </div>
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
           <p className="text-xs text-gray-500 font-mono mb-3">
              Viewing as: {currentUser.name} ({currentUser.role})
            </p>

           <div className="h-64 w-full flex gap-4">
              <div className="flex-1">
                 <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={barData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis dataKey="role" stroke="#9ca3af" fontSize={10} />
                      <YAxis stroke="#9ca3af" fontSize={10} />
                      <Tooltip 
                        contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', color: '#f3f4f6' }}
                        cursor={{fill: '#374151', opacity: 0.4}}
                      />
                      <Legend />
                      <Bar dataKey="allowed" stackId="a" fill="#10b981" name="Allowed" />
                      <Bar dataKey="denied" stackId="a" fill="#ef4444" name="Denied" />
                    </BarChart>
                 </ResponsiveContainer>
              </div>
              <div className="w-48">
                 <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={60}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {pieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                 </ResponsiveContainer>
              </div>
           </div>
        </div>

        {/* AI Insight */}
        <div className="bg-surface p-4 rounded-lg border border-gray-700 flex flex-col">
          <h3 className="text-gray-300 font-bold mb-4 flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            SOC AI Analyst
          </h3>
          <div className="bg-black/30 p-4 rounded border border-gray-800 flex-1 text-sm text-gray-400 font-mono leading-relaxed">
            {analysis}

          </div>
        </div>
      </div>

      {/* Logs Table */}
      <div className="bg-surface rounded-lg border border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-700 bg-gray-900/50 flex justify-between items-center">
            <h3 className="text-gray-300 font-bold">Recent Access Logs</h3>
            <span className="text-xs text-gray-500 font-mono">Live Monitoring Active</span>
        </div>
        <div className="overflow-x-auto max-h-64 overflow-y-auto">
          <table className="w-full text-left text-xs font-mono text-gray-400">
            <thead className="bg-gray-800 text-gray-200 uppercase tracking-wider">
              <tr>
                <th className="px-6 py-3">Timestamp</th>
                <th className="px-6 py-3">User</th>
                <th className="px-6 py-3">Role</th>
                <th className="px-6 py-3">Action</th>
                <th className="px-6 py-3">Resource</th>
                <th className="px-6 py-3">Reason</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-white/5 transition-colors">
                  <td className="px-6 py-2">{new Date(log.timestamp).toLocaleTimeString()}</td>
                  <td className="px-6 py-2 font-bold text-gray-300">{log.userName}</td>
                  <td className="px-6 py-2">{log.userRole}</td>
                  <td className="px-6 py-2">
                    <span className={`px-2 py-1 rounded ${log.result === 'ALLOWED' ? 'bg-emerald-500/10 text-emerald-500' : 'bg-red-500/10 text-red-500'}`}>
                      {log.result}
                    </span>
                  </td>
                  <td className="px-6 py-2">{log.documentTitle}</td>
                  <td className="px-6 py-2 opacity-70">{log.reason}</td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr>
                   <td colSpan={6} className="px-6 py-8 text-center text-gray-600">No logs generated yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};