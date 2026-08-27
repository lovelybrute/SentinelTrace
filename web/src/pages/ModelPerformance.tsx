import React, { useEffect, useState } from 'react';
import { BrainCircuit, Database, ShieldCheck, AlertTriangle } from 'lucide-react';
import { fetchModelMetrics, type ModelMetrics } from '@/services/backendService';

export function ModelPerformance() {
  const [data, setData] = useState<ModelMetrics | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    fetchModelMetrics(controller.signal)
      .then(result => {
        if (!controller.signal.aborted) {
          setData(result);
          setError('');
        }
      })
      .catch(e => {
        if (!controller.signal.aborted) {
          setError(e instanceof Error ? e.message : 'Metrics unavailable');
        }
      });
    return () => controller.abort();
  }, []);
  const selected = data?.selected_model ? data.models?.[data.selected_model] : undefined;
  const percent = (value?: number) => value === undefined ? '—' : `${(value * 100).toFixed(1)}%`;
  return (
    <div className="space-y-6" style={{ padding: 24, maxWidth: 1200, margin: '0 auto' }}>
      <div className="flex items-center gap-3">
        <BrainCircuit size={24} color="#22d3ee" />
        <div><h1 className="text-xl font-extrabold text-slate-100">AI Model Performance</h1><p className="text-xs text-slate-400">Same-corpus holdout and independent validation are reported separately</p></div>
      </div>
      {error && <div className="panel p-5 text-red-400">{error}</div>}
      {data?.validation_status === 'NOT_TRAINED' && (
        <div className="panel p-6 border border-amber-500/30"><div className="flex gap-3"><AlertTriangle color="#f59e0b"/><div><div className="font-bold text-amber-400">Validated model not trained yet</div><p className="text-sm text-slate-400 mt-1">{data.message}</p><code className="block mt-4 text-xs text-cyan-300">python ml/prepare_dataset.py ... &amp;&amp; python ml/train_model.py</code></div></div></div>
      )}
      {data && data.validation_status !== 'NOT_TRAINED' && <>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[['Accuracy', selected?.accuracy], ['Precision', selected?.precision_macro], ['Recall', selected?.recall_macro], ['Macro F1', selected?.f1_macro]].map(([label, value]) => <div className="panel p-5" key={String(label)}><div className="text-xs text-slate-400">{label}</div><div className="text-2xl font-black text-cyan-300 mt-2">{percent(value as number | undefined)}</div></div>)}
        </div>
        <div className="grid md:grid-cols-2 gap-5">
          <div className="panel p-5"><div className="flex items-center gap-2 font-bold"><Database size={16}/>Dataset evidence</div><dl className="mt-4 text-sm space-y-2 text-slate-300"><div>Corpus: {data.dataset_name || 'User-supplied corpus'}</div><div>Records: {data.dataset_records}</div><div>Train/Test: {data.train_records} / {data.test_records}</div><div>Labels: {data.labels?.join(', ')}</div><div>Model: {data.selected_model}</div>{data.dataset_citation && <div className="text-xs text-slate-400 break-words">Citation: {data.dataset_citation}</div>}</dl></div>
          <div className="panel p-5"><div className="flex items-center gap-2 font-bold"><ShieldCheck size={16}/>Validation status</div><div className="mt-4 font-mono text-cyan-300">{data.validation_status}</div><p className="text-sm text-slate-400 mt-3">{data.limitations}</p></div>
        </div>
        {data.external_validation && (
          <div className="panel p-5 border border-cyan-500/25">
            <div className="flex items-center gap-2 font-bold text-cyan-300"><ShieldCheck size={16}/>Independent validation</div>
            <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3">
              <div><div className="text-xs text-slate-500">Records</div><div className="text-xl font-black text-slate-100">{data.external_validation.records.toLocaleString()}</div></div>
              <div><div className="text-xs text-slate-500">Accuracy</div><div className="text-xl font-black text-cyan-300">{percent(data.external_validation.after.accuracy)}</div></div>
              <div><div className="text-xs text-slate-500">Macro F1</div><div className="text-xl font-black text-cyan-300">{percent(data.external_validation.after.f1_macro)}</div></div>
              <div><div className="text-xs text-slate-500">F1 improvement</div><div className="text-xl font-black text-emerald-300">+{percent(data.external_validation.delta.f1_macro)}</div></div>
            </div>
            <p className="mt-4 text-sm text-slate-300">{data.external_validation.dataset_name}</p>
            <p className="mt-1 text-xs text-slate-500 break-words">{data.external_validation.dataset_citation}</p>
            <p className="mt-3 text-xs text-amber-300">{data.external_validation.limitations}</p>
          </div>
        )}
        {data.label_scope && <div className="panel p-5 border border-amber-500/20"><div className="flex items-center gap-2 font-bold text-amber-300"><AlertTriangle size={16}/>Label scope</div><p className="text-sm text-slate-400 mt-3">{data.label_scope}</p></div>}
      </>}
    </div>
  );
}
