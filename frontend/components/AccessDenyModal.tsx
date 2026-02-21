import React from 'react';
import { AccessLog } from '../types';

interface AccessDenyModalProps {
  log: AccessLog | null;
  onClose: () => void;
}

export const AccessDenyModal: React.FC<AccessDenyModalProps> = ({ log, onClose }) => {
  if (!log) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-surface border-2 border-danger rounded-lg max-w-md w-full shadow-[0_0_50px_rgba(239,68,68,0.5)] overflow-hidden animate-bounce-in">
        <div className="bg-danger/20 p-4 border-b border-danger flex items-center justify-between">
          <h2 className="text-danger font-bold text-xl flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            ACCESS DENIED
          </h2>
          <button onClick={onClose} className="text-danger hover:text-white transition-colors">
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="p-6 space-y-4">
          <div className="text-center">
            <div className="text-6xl mb-4">🚫</div>
            <p className="text-gray-300">You do not have permission to view:</p>
            <p className="text-white font-mono font-bold text-lg mt-1">{log.documentTitle}</p>
          </div>
          
          <div className="bg-black/40 p-3 rounded border border-gray-700 font-mono text-xs text-danger">
            <p>ERROR_CODE: 403_FORBIDDEN</p>
            <p>USER: {log.userName}</p>
            <p>ROLE: {log.userRole}</p>
            <p>REASON: {log.reason}</p>
            <p>TIMESTAMP: {new Date(log.timestamp).toISOString()}</p>
            <p>TRACE_ID: {log.id.split('-')[0]}</p>
          </div>

          <p className="text-xs text-gray-500 text-center">
            This attempt has been logged. Repeated unauthorized attempts will be flagged to the Security Operations Center.
          </p>
          
          <button 
            onClick={onClose}
            className="w-full bg-danger hover:bg-red-600 text-white font-bold py-2 px-4 rounded transition-colors"
          >
            ACKNOWLEDGE
          </button>
        </div>
      </div>
    </div>
  );
};