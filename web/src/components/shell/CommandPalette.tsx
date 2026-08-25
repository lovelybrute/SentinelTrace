import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  Shield,
  FileSearch,
  GitBranch,
  Globe,
  Network,
  Layers,
  FolderLock,
  FileText,
  Bell,
  Settings,
  Sparkles,
  Zap,
  CornerDownLeft,
} from 'lucide-react';
import { DEMO_EMAIL_RAW, DEMO_EMAIL_FILENAME } from '@/demo/demoEmail';
import { analyseEmail } from '@/services/analysisService';
import { useAnalysis } from '@/context/AnalysisContext';

export function CommandPalette({
  isOpen,
  onClose,
  onOpenCopilot,
}: {
  isOpen: boolean;
  onClose: () => void;
  onOpenCopilot?: () => void;
}) {
  const navigate = useNavigate();
  const { setCurrentAnalysis, addToHistory } = useAnalysis();
  const [searchTerm, setSearchTerm] = useState('');
  const [loadingDemo, setLoadingDemo] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
        else onClose(); // parent handles toggle
      }
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleAction = (route: string) => {
    navigate(route);
    onClose();
  };

  const handleLoadDemo = async () => {
    setLoadingDemo(true);
    try {
      const outcome = await analyseEmail({
        raw: DEMO_EMAIL_RAW,
        filename: DEMO_EMAIL_FILENAME,
        analystId: 'COMMAND_PALETTE',
        acquisitionSource: 'Command Palette Ingest',
        useBackend: true,
      });
      setCurrentAnalysis(outcome.analysis);
      addToHistory(outcome.analysis);
      navigate('/analyzer');
      onClose();
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingDemo(false);
    }
  };

  const commands = [
    { label: 'Analyze Email (MIME Ingestion)', category: 'Core Forensics', icon: <FileSearch size={14} />, action: () => handleAction('/analyzer') },
    { label: 'Load Pre-Configured BEC Attack Demo', category: 'Attack Vectors', icon: <Zap size={14} className="text-amber-400" />, action: handleLoadDemo },
    { label: 'Open SOC Dashboard', category: 'Navigation', icon: <Shield size={14} />, action: () => handleAction('/dashboard') },
    { label: 'RFC 5322 & Header Forensics', category: 'Core Forensics', icon: <FileText size={14} />, action: () => handleAction('/header-forensics') },
    { label: 'SMTP Relay Path & Hop Timeline', category: 'Core Forensics', icon: <GitBranch size={14} />, action: () => handleAction('/relay-chain') },
    { label: 'Origin Infrastructure & Geolocation', category: 'Intelligence', icon: <Globe size={14} />, action: () => handleAction('/origin-trace') },
    { label: 'Interactive 3D Threat Graph', category: 'Intelligence', icon: <Network size={14} />, action: () => handleAction('/graph') },
    { label: 'Cross-Email Campaign Correlator', category: 'Intelligence', icon: <Layers size={14} />, action: () => handleAction('/campaigns') },
    { label: 'MITRE ATT&CK & STIX 2.1 Threat Intel', category: 'Intelligence', icon: <Shield size={14} />, action: () => handleAction('/threat-intel') },
    { label: 'SOC Case Management & Chain of Custody', category: 'Operations', icon: <FolderLock size={14} />, action: () => handleAction('/cases') },
    { label: 'Generate & Export Forensic Reports', category: 'Operations', icon: <FileText size={14} />, action: () => handleAction('/reports') },
    { label: 'Ask AI Forensic Copilot', category: 'AI Assistant', icon: <Sparkles size={14} className="text-cyan-400" />, action: () => { onClose(); onOpenCopilot?.(); } },
  ];

  const filteredCommands = commands.filter((c) =>
    c.label.toLowerCase().includes(searchTerm.toLowerCase()) ||
    c.category.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 px-4 bg-black/75 backdrop-blur-md animate-fade-in">
      <div className="w-full max-w-2xl rounded-2xl bg-[#080e21] border border-cyan-500/30 shadow-[0_0_50px_rgba(0,0,0,0.9)] overflow-hidden">
        {/* Search Input */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-cyan-500/20 bg-[#050a18]">
          <Search size={18} className="text-cyan-400" />
          <input
            type="text"
            autoFocus
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Type a command, search IOC, or jump to forensic module..."
            className="flex-1 bg-transparent border-none text-sm text-slate-100 placeholder-slate-500 focus:outline-none font-mono"
          />
          <div className="flex items-center gap-1 text-[10px] font-mono text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded border border-slate-700">
            ESC to close
          </div>
        </div>

        {/* Command List */}
        <div className="max-h-96 overflow-y-auto p-2 space-y-1">
          {filteredCommands.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 font-mono">
              No matching commands or modules found.
            </div>
          ) : (
            filteredCommands.map((cmd, idx) => (
              <button
                key={cmd.label}
                onClick={cmd.action}
                className="w-full flex items-center justify-between p-3 rounded-lg text-left text-xs text-slate-200 hover:bg-cyan-950/50 hover:text-cyan-300 hover:border-cyan-500/40 border border-transparent transition-all group"
              >
                <div className="flex items-center gap-3">
                  <span className="p-1.5 rounded-md bg-slate-800/80 text-cyan-400 group-hover:bg-cyan-900/60 transition-colors">
                    {cmd.icon}
                  </span>
                  <div>
                    <div className="font-semibold">{cmd.label}</div>
                    <div className="text-[10px] text-slate-500 group-hover:text-cyan-400/70 font-mono">
                      {cmd.category}
                    </div>
                  </div>
                </div>
                <CornerDownLeft size={13} className="text-slate-600 group-hover:text-cyan-400 transition-colors" />
              </button>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-2 bg-[#050a18] border-t border-cyan-500/10 text-[10px] font-mono text-slate-400">
          <span>SentinelTrace Fast Investigation Palette</span>
          <span className="text-cyan-400">Ctrl + K</span>
        </div>
      </div>
    </div>
  );
}
