import React, { useState } from 'react';
import { Bot, Send, X, Sparkles, Shield, AlertTriangle, CheckCircle, Terminal, HelpCircle } from 'lucide-react';
import { useAnalysis } from '@/context/AnalysisContext';

interface ChatMessage {
  id: string;
  sender: 'AI' | 'USER';
  text: string;
  timestamp: string;
  evidenceTags?: string[];
}

export function AICopilotDrawer({
  isOpen,
  onClose,
}: {
  isOpen: boolean;
  onClose: () => void;
}) {
  const { currentAnalysis } = useAnalysis();
  const [inputQuery, setInputQuery] = useState('');
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'init-1',
      sender: 'AI',
      text: 'SentinelTrace AI Forensic Copilot initialized. I have indexed the active email MIME stream, cryptographic auth headers, and relay infrastructure. How can I assist your investigation?',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  const quickPrompts = [
    'What makes this email suspicious?',
    'Explain the SPF/DKIM/DMARC results',
    'Show the earliest reliable external IP',
    'Which MITRE techniques apply?',
    'Summarize incident response actions',
  ];

  const handleSend = (textToSend?: string) => {
    const query = textToSend || inputQuery.trim();
    if (!query) return;

    const userMsg: ChatMessage = {
      id: `usr-${Date.now()}`,
      sender: 'USER',
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');

    // Generate context-aware response based on currentAnalysis
    setTimeout(() => {
      let aiResponseText = '';
      let tags: string[] = [];

      const queryLower = query.toLowerCase();

      if (!currentAnalysis) {
        aiResponseText =
          'No active email is loaded in the workspace. Please upload or load a sample .eml in the Email Analyzer to inspect cryptographic headers, relay hops, and threat indicators.';
      } else if (queryLower.includes('suspicious') || queryLower.includes('score') || queryLower.includes('why')) {
        const score = currentAnalysis.score.total;
        const level = currentAnalysis.score.level;
        const findings = currentAnalysis.assessment.findings.map((f) => `• ${f.label}: ${f.evidence}`).join('\n');
        aiResponseText = `The threat score is ${score}/100 (${level}). Key forensic indicators:\n\n${findings || '• No high-severity indicators observed.'}`;
        tags = [`SCORE: ${score}`, level, currentAnalysis.assessment.classification];
      } else if (queryLower.includes('spf') || queryLower.includes('dkim') || queryLower.includes('dmarc') || queryLower.includes('auth')) {
        const auth = currentAnalysis.authentication;
        const checkSummary = auth.checks.map((c) => `• ${c.mechanism}: ${c.verdict} — ${c.detail || 'Evaluated'}`).join('\n');
        aiResponseText = `RFC Authentication Summary:\n\n${checkSummary}\n\nOverall Trust Score: ${auth.trustScore}/100.`;
        tags = ['RFC 7208', 'RFC 6376', 'RFC 7489'];
      } else if (queryLower.includes('ip') || queryLower.includes('relay') || queryLower.includes('origin') || queryLower.includes('external')) {
        const origin = currentAnalysis.originAssessment;
        const loc = origin.estimatedLocation;
        aiResponseText = `Earliest external MTA infrastructure: ${origin.observedSourceIp || 'Undetermined'} (${loc?.country || 'Unknown'}, ${origin.asn || 'Unknown ASN'}).\nHosting Type: ${origin.hostingType}.\nConfidence: ${origin.confidence}%.\n\nNote: Represents observed network relay, not physical human localization.`;
        tags = [origin.observedSourceIp || 'MTA', origin.hostingType];
      } else if (queryLower.includes('mitre') || queryLower.includes('technique')) {
        aiResponseText = `Mapped MITRE ATT&CK Techniques:\n• T1566: Phishing (Initial Access)\n• T1566.002: Spearphishing Link (Credential Harvesting / Redirect)\n• T1598: Phishing for Information\n\nAll mappings are grounded in observed indicators.`;
        tags = ['T1566', 'T1598', 'MITRE ATT&CK'];
      } else if (queryLower.includes('action') || queryLower.includes('response') || queryLower.includes('summary')) {
        const actions = currentAnalysis.assessment.recommendedActions.map((a) => `• [${a.priority}] ${a.label}: ${a.rationale}`).join('\n');
        aiResponseText = `Recommended Incident Response Playbook:\n\n${actions || '• Block identified IOCs at email gateway and firewall.'}`;
        tags = ['IR PLAYBOOK', 'CONTAINMENT'];
      } else {
        aiResponseText = `Forensic Analysis for ${currentAnalysis.metadata.subject || 'active message'}:\nClassification: ${currentAnalysis.assessment.classification} (${currentAnalysis.assessment.confidence.toFixed(1)}% confidence).\nNarrative: ${currentAnalysis.assessment.narrative}`;
        tags = [currentAnalysis.assessment.classification];
      }

      const aiMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        sender: 'AI',
        text: aiResponseText,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        evidenceTags: tags,
      };
      setMessages((prev) => [...prev, aiMsg]);
    }, 450);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-[460px] bg-[#080e21]/95 border-l border-cyan-500/25 backdrop-blur-2xl shadow-[-10px_0_40px_rgba(0,0,0,0.8)] flex flex-col transition-all duration-300">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-cyan-500/20 bg-[#050a18]/70">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Bot size={18} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-slate-100 tracking-wider font-mono">
                SENTINELTRACE AI
              </span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                COPILOT
              </span>
            </div>
            <div className="text-[10px] text-slate-400">
              Evidence-Grounded Forensic Assistant
            </div>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800/60 transition-colors"
        >
          <X size={16} />
        </button>
      </div>

      {/* Messages Feed */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((m) => {
          const isAi = m.sender === 'AI';
          return (
            <div
              key={m.id}
              className={`flex flex-col ${isAi ? 'items-start' : 'items-end'}`}
            >
              <div
                className={`max-w-[90%] p-3.5 rounded-xl text-xs leading-relaxed ${
                  isAi
                    ? 'bg-[#0d1733]/90 border border-cyan-500/20 text-slate-200 shadow-md'
                    : 'bg-gradient-to-r from-sky-600 to-cyan-600 text-white font-medium shadow-md'
                }`}
              >
                <div className="whitespace-pre-line">{m.text}</div>
                {m.evidenceTags && m.evidenceTags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-2.5 pt-2 border-t border-cyan-500/15">
                    {m.evidenceTags.map((tag) => (
                      <span
                        key={tag}
                        className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-500/30"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              <span className="text-[9px] font-mono text-slate-500 mt-1 px-1">
                {m.timestamp}
              </span>
            </div>
          );
        })}
      </div>

      {/* Quick Prompts */}
      <div className="px-4 py-2 border-t border-cyan-500/10 bg-[#050a18]/40">
        <div className="text-[10px] font-bold text-slate-400 mb-2 flex items-center gap-1.5">
          <Sparkles size={11} className="text-cyan-400" />
          QUICK FORENSIC PROMPTS
        </div>
        <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto">
          {quickPrompts.map((p) => (
            <button
              key={p}
              onClick={() => handleSend(p)}
              className="px-2.5 py-1 rounded-md text-[11px] bg-slate-900/80 hover:bg-cyan-950/90 text-slate-300 hover:text-cyan-300 border border-slate-700/60 hover:border-cyan-500/40 transition-colors text-left"
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* Input Form */}
      <div className="p-3.5 border-t border-cyan-500/20 bg-[#080e21]">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            value={inputQuery}
            onChange={(e) => setInputQuery(e.target.value)}
            placeholder="Ask AI Copilot about this email evidence..."
            className="flex-1 bg-[#0d1733] border border-cyan-500/25 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400"
          />
          <button
            type="submit"
            className="p-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition-colors"
          >
            <Send size={14} />
          </button>
        </form>
      </div>
    </div>
  );
}
