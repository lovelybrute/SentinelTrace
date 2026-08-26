import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderPlus, Search, PlusCircle, Download, FileText, Share2,
  Package, CheckCircle, ShieldAlert, Sparkles, ExternalLink, Zap
} from 'lucide-react';
import type { EmailAnalysis } from '@/types';
import { exportInvestigationPackage } from '@/services/evidenceExporter';

interface AnalystActionCenterProps {
  analysis: EmailAnalysis;
  onOpenCaseModal?: () => void;
}

export function AnalystActionCenter({ analysis, onOpenCaseModal }: AnalystActionCenterProps) {
  const navigate = useNavigate();
  const [downloadingPackage, setDownloadingPackage] = useState(false);
  const [copiedIocStatus, setCopiedIocStatus] = useState<string | null>(null);

  const handleExportPackage = async () => {
    setDownloadingPackage(true);
    try {
      await exportInvestigationPackage(analysis);
    } catch (e) {
      console.error(e);
    } finally {
      setDownloadingPackage(false);
    }
  };

  const handleCopyIocs = () => {
    const iocList = analysis.iocs.map(i => `[${i.type}] ${i.value} (${i.reputation})`).join('\n');
    navigator.clipboard.writeText(iocList);
    setCopiedIocStatus('IOCs Copied to Clipboard!');
    setTimeout(() => setCopiedIocStatus(null), 2000);
  };

  return (
    <div className="panel p-6 border-cyan-500/25 bg-[#080e21] shadow-[0_0_30px_rgba(0,0,0,0.5)] space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyan-500/15 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_12px_rgba(34,211,238,0.3)]">
            <Zap size={16} />
          </div>
          <div>
            <div className="font-mono text-xs font-bold text-slate-100 uppercase tracking-wider">
              ANALYST ACTION CENTER & TRIAGE PLAYBOOK
            </div>
            <div className="text-[11px] text-slate-400">
              Immediate evidence preservation, case creation, global search, and CTI export
            </div>
          </div>
        </div>

        {copiedIocStatus && (
          <div className="flex items-center gap-1.5 px-3 py-1 rounded bg-emerald-950/80 border border-emerald-500/40 text-emerald-400 text-xs font-mono">
            <CheckCircle size={13} />
            <span>{copiedIocStatus}</span>
          </div>
        )}
      </div>

      {/* Action Buttons Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Action 1: Create Case */}
        <button
          onClick={() => {
            if (onOpenCaseModal) onOpenCaseModal();
            else navigate('/cases');
          }}
          className="p-3.5 rounded-xl bg-[#0d1733] hover:bg-emerald-950/40 border border-slate-800 hover:border-emerald-500/50 text-left transition-all group flex flex-col justify-between"
        >
          <FolderPlus size={18} className="text-emerald-400 group-hover:scale-110 transition-transform mb-2" />
          <div>
            <div className="font-mono text-xs font-bold text-slate-200 group-hover:text-emerald-300">
              CREATE CASE
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">
              Open SOC Incident
            </div>
          </div>
        </button>

        {/* Action 2: Search Related Emails */}
        <button
          onClick={() => navigate(`/threat-intel`)}
          className="p-3.5 rounded-xl bg-[#0d1733] hover:bg-cyan-950/40 border border-slate-800 hover:border-cyan-500/50 text-left transition-all group flex flex-col justify-between"
        >
          <Search size={18} className="text-cyan-400 group-hover:scale-110 transition-transform mb-2" />
          <div>
            <div className="font-mono text-xs font-bold text-slate-200 group-hover:text-cyan-300">
              SEARCH RELATED
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">
              Cross-Email Search
            </div>
          </div>
        </button>

        {/* Action 3: Add / Copy IOCs */}
        <button
          onClick={handleCopyIocs}
          className="p-3.5 rounded-xl bg-[#0d1733] hover:bg-sky-950/40 border border-slate-800 hover:border-sky-500/50 text-left transition-all group flex flex-col justify-between"
        >
          <PlusCircle size={18} className="text-sky-400 group-hover:scale-110 transition-transform mb-2" />
          <div>
            <div className="font-mono text-xs font-bold text-slate-200 group-hover:text-sky-300">
              ADD / COPY IOCs
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">
              {analysis.iocs.length} Extracted IOCs
            </div>
          </div>
        </button>

        {/* Action 4: Generate Report */}
        <button
          onClick={() => navigate('/reports')}
          className="p-3.5 rounded-xl bg-[#0d1733] hover:bg-amber-950/40 border border-slate-800 hover:border-amber-500/50 text-left transition-all group flex flex-col justify-between"
        >
          <FileText size={18} className="text-amber-400 group-hover:scale-110 transition-transform mb-2" />
          <div>
            <div className="font-mono text-xs font-bold text-slate-200 group-hover:text-amber-300">
              GENERATE REPORT
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">
              HTML / JSON Format
            </div>
          </div>
        </button>

        {/* Action 5: Export STIX 2.1 */}
        <button
          onClick={() => {
            const stixData = {
              type: 'bundle',
              id: `bundle--${analysis.evidence.evidenceId.toLowerCase()}`,
              objects: analysis.iocs.map(ioc => ({
                type: 'indicator',
                id: `indicator--${ioc.id}`,
                name: `${ioc.type}: ${ioc.value}`,
                pattern: `[${ioc.type.toLowerCase()}-addr:value = '${ioc.value}']`,
              })),
            };
            const blob = new Blob([JSON.stringify(stixData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `stix2.1_${analysis.evidence.evidenceId}.json`;
            a.click();
          }}
          className="p-3.5 rounded-xl bg-[#0d1733] hover:bg-purple-950/40 border border-slate-800 hover:border-purple-500/50 text-left transition-all group flex flex-col justify-between"
        >
          <Share2 size={18} className="text-purple-400 group-hover:scale-110 transition-transform mb-2" />
          <div>
            <div className="font-mono text-xs font-bold text-slate-200 group-hover:text-purple-300">
              EXPORT STIX 2.1
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">
              OASIS CTI Bundle
            </div>
          </div>
        </button>

        {/* Action 6: Export Investigation Package */}
        <button
          onClick={handleExportPackage}
          disabled={downloadingPackage}
          className="p-3.5 rounded-xl bg-gradient-to-br from-cyan-950 to-sky-950 hover:from-cyan-900 hover:to-sky-900 border border-cyan-500/40 text-left transition-all group flex flex-col justify-between shadow-[0_0_15px_rgba(6,182,212,0.2)]"
        >
          <Package size={18} className="text-cyan-300 group-hover:scale-110 transition-transform mb-2" />
          <div>
            <div className="font-mono text-xs font-bold text-cyan-200">
              {downloadingPackage ? 'BUNDLING...' : 'PACKAGE EXPORT'}
            </div>
            <div className="text-[10px] text-cyan-400/80 font-mono mt-0.5">
              Full Evidence Zip
            </div>
          </div>
        </button>
      </div>
    </div>
  );
}
