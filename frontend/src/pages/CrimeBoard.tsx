import React, { useEffect, useState } from 'react';
import { Shield, FileSearch, CheckCircle2, AlertTriangle } from 'lucide-react';
import { api } from '../services/api';

const CrimeBoard: React.FC = () => {
  const [cases, setCases] = useState<any[]>([]);
  const [selectedCase, setSelectedCase] = useState<any | null>(null);
  const [error, setError] = useState('');

  const loadCases = async () => {
    try {
      const resp = await api.get('/crime/cases');
      setCases(resp.data.cases || []);
      setError('');
    } catch (err) {
      console.error(err);
      setError('Unable to load crime cases. Is the backend running?');
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  const handleSelectCase = async (caseItem: any) => {
    try {
      const resp = await api.get(`/crime/cases/${caseItem.id}`);
      setSelectedCase(resp.data);
      setError('');
    } catch (err) {
      console.error(err);
      setError('Could not load selected case details.');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-display font-bold text-white">Investigation Case Board</h1>
          <p className="text-slate-400 mt-1">Mock Cyber Crime integration and case evidence chain verification.</p>
        </div>
        <button
          onClick={loadCases}
          className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-xl text-sm font-semibold text-white"
        >
          <FileSearch size={16} />
          Refresh cases
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-200">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-[360px_minmax(0,1fr)] gap-6">
        <div className="glass-card p-6 space-y-4">
          <div className="flex items-center gap-3 text-slate-200">
            <Shield size={18} />
            <h2 className="text-lg font-semibold">Recent Cases</h2>
          </div>
          <div className="space-y-3">
            {cases.length === 0 ? (
              <div className="text-slate-500 text-sm">No cases found. High-severity alerts create mock cases automatically.</div>
            ) : (
              cases.map((caseItem) => (
                <button
                  key={caseItem.id}
                  onClick={() => handleSelectCase(caseItem)}
                  className="w-full text-left p-4 rounded-2xl border border-slate-800 bg-slate-950 hover:bg-slate-900 transition"
                >
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-sm font-semibold text-slate-100">{caseItem.title}</span>
                    <span className="text-[11px] uppercase tracking-[0.24em] text-slate-500">Case #{caseItem.id}</span>
                  </div>
                  <p className="mt-2 text-slate-400 text-sm line-clamp-2">{caseItem.description}</p>
                  <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
                    <span>{caseItem.reporter}</span>
                    <span>{new Date(caseItem.created_at).toLocaleString()}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        <div className="glass-card p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3 text-slate-200">
              <CheckCircle2 size={18} />
              <h2 className="text-lg font-semibold">Case Details</h2>
            </div>
            <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Evidence Chain</span>
          </div>

          {!selectedCase ? (
            <div className="text-slate-500 text-sm">Select a case to inspect its evidence chain and metadata.</div>
          ) : (
            <div className="space-y-5">
              <div className="rounded-3xl border border-slate-800 p-5 bg-slate-950">
                <h3 className="text-sm font-semibold text-slate-200">{selectedCase.title}</h3>
                <p className="mt-2 text-slate-400 text-sm">{selectedCase.description}</p>
                <div className="mt-4 grid grid-cols-2 gap-3 text-xs text-slate-500">
                  <div>
                    <span className="block text-slate-400">Reporter</span>
                    <span>{selectedCase.reporter}</span>
                  </div>
                  <div>
                    <span className="block text-slate-400">Created</span>
                    <span>{new Date(selectedCase.created_at).toLocaleString()}</span>
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center gap-2 text-slate-300">
                  <AlertTriangle size={16} />
                  <span className="uppercase tracking-[0.24em] text-slate-500 text-xs">Attached Evidence</span>
                </div>
                {selectedCase.evidence.length === 0 ? (
                  <div className="text-slate-500 text-sm">No evidence attached to this case yet.</div>
                ) : (
                  selectedCase.evidence.map((ev: any) => (
                    <div key={ev.id} className="rounded-2xl border border-slate-800 bg-slate-950 p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="text-sm font-semibold text-slate-100">{ev.file_name}</p>
                          <p className="text-xs text-slate-500 mt-1">Evidence ID: {ev.evidence_id}</p>
                        </div>
                        <span className="text-[11px] text-slate-500">{new Date(ev.created_at).toLocaleString()}</span>
                      </div>
                      <div className="mt-3 text-slate-400 text-sm">
                        {ev.metadata ? JSON.stringify(ev.metadata, null, 2) : 'No metadata available.'}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CrimeBoard;
