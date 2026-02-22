import React from 'react';

interface TerminationOverlayProps {
  countdown: number;
}

export const TerminationOverlay: React.FC<TerminationOverlayProps> = ({ countdown }) => {
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/95 backdrop-blur-md p-4">
      <div className="max-w-xl w-full bg-vault-surface border-2 border-danger rounded-xl p-8 text-center shadow-[0_0_60px_rgba(239,68,68,0.45)]">
        <p className="text-danger text-xs font-bold tracking-[0.3em] uppercase mb-4">Session Security Enforcement</p>
        <h2 className="text-2xl md:text-3xl font-bold text-text-primary mb-3">Termination Pending</h2>
        <p className="text-text-secondary mb-6">Your current session will be terminated in <span className="text-danger font-bold">{countdown}</span> seconds.</p>
        <div className="mx-auto w-24 h-24 rounded-full border-4 border-danger flex items-center justify-center text-4xl font-black text-danger animate-pulse">
          {countdown}
        </div>
        <p className="mt-6 text-xs text-text-muted">Interaction is locked until countdown completes.</p>
      </div>
    </div>
  );
};
