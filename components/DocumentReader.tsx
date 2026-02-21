import React, { useEffect, useRef, useState } from 'react';
import { Document, User } from '../types';

interface DocumentReaderProps {
  document: Document;
  user: User;
  onClose: () => void;
}

export const DocumentReader: React.FC<DocumentReaderProps> = ({ document, user, onClose }) => {
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(true);
  const closeRef = useRef<HTMLButtonElement>(null);

  // Deterministic display session token — timestamp in base-36, no Math.random
  const displayToken = `${user.id.toUpperCase()}-${Date.now().toString(36).toUpperCase()}`;

  useEffect(() => {
    setLoading(true);
    const fakeContent =
`DOCUMENT ID: ${document.id}
TITLE: ${document.title}

This is a secure ${document.classification} document
belonging to the ${document.department} department.

Access granted under Zero Trust Policy.

User:      ${user.name} [${user.role}]
Timestamp: ${new Date().toLocaleString()}
Token:     ${displayToken}`;

    const t = setTimeout(() => { setContent(fakeContent); setLoading(false); }, 800);
    return () => clearTimeout(t);
  }, [document, user]);

  // Focus the close button when modal opens (accessibility)
  useEffect(() => { closeRef.current?.focus(); }, []);

  // Trap Escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="doc-reader-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 backdrop-blur-md p-4"
    >
      <div className="bg-surface border border-primary/50 rounded-lg max-w-2xl w-full shadow-[0_0_30px_rgba(59,130,246,0.3)] flex flex-col max-h-[80vh]">
        {/* Header */}
        <div className="bg-primary/10 p-4 border-b border-primary/30 flex items-center justify-between">
          <div>
            <h2 id="doc-reader-title" className="text-primary font-bold text-xl flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              {document.title}
            </h2>
            <div className="flex gap-2 mt-1">
              <span className={`text-[10px] uppercase px-2 py-0.5 rounded border ${
                document.classification === 'Public'       ? 'border-accent text-accent' :
                document.classification === 'Internal'     ? 'border-primary text-primary' :
                document.classification === 'Confidential' ? 'border-warning text-warning' :
                'border-danger text-danger'
              }`}>{document.classification}</span>
              <span className="text-[10px] text-gray-400 uppercase px-2 py-0.5 rounded border border-gray-700">
                Owner: {document.department}
              </span>
            </div>
          </div>
          <button
            ref={closeRef}
            onClick={onClose}
            aria-label="Close document"
            className="text-gray-400 hover:text-white transition-colors"
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Content */}
        <div className="p-8 overflow-y-auto flex-1 font-mono text-sm leading-relaxed text-gray-300 relative">
          {loading ? (
            <div className="flex flex-col items-center justify-center h-full space-y-4">
              <div className="w-12 h-12 border-4 border-primary border-t-transparent rounded-full animate-spin" />
              <p className="text-primary animate-pulse">Decrypting via Secure Channel...</p>
            </div>
          ) : (
            <div className="prose prose-invert max-w-none">
              {(document.classification === 'Restricted' || document.classification === 'Confidential') && (
                <div className="mb-6 p-2 border border-dashed border-danger/50 text-danger/80 text-xs text-center">
                  WARNING: THIS DOCUMENT IS WATERMARKED FOR {user.name.toUpperCase()} [{user.id}]. DO NOT DISTRIBUTE.
                </div>
              )}
              <pre className="whitespace-pre-wrap">{content}</pre>
            </div>
          )}
          <div className="absolute inset-0 pointer-events-none flex items-center justify-center opacity-5 select-none overflow-hidden" aria-hidden="true">
            <span className="transform -rotate-45 text-6xl font-black text-white whitespace-nowrap">
              CONFIDENTIAL • {user.name.toUpperCase()} • {new Date().toLocaleDateString()}
            </span>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-700/50 bg-black/20 text-xs text-gray-500 flex justify-between font-mono">
          <span>Token: {displayToken}</span>
          <span>Zero Trust Access Verified</span>
        </div>
      </div>
    </div>
  );
};
