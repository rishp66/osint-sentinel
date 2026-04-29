import React, { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Bot, ChevronDown, ChevronUp, FileText } from 'lucide-react';

const mdComponents = {
  h3: ({ children }) => (
    <h3 className="font-display text-base font-bold text-white mt-7 mb-3 pb-2 border-b border-sentinel-purple/20 flex items-center gap-2">
      <span className="w-1 h-4 bg-sentinel-purple rounded-full flex-shrink-0" />
      {children}
    </h3>
  ),
  h4: ({ children }) => (
    <h4 className="font-display text-sm font-semibold text-sentinel-purple-light mt-4 mb-2">
      {children}
    </h4>
  ),
  p: ({ children }) => (
    <p className="text-sentinel-text-dim text-sm font-body leading-relaxed mb-3">{children}</p>
  ),
  ul: ({ children }) => (
    <ul className="space-y-1.5 mb-4 ml-1">{children}</ul>
  ),
  ol: ({ children }) => (
    <ol className="space-y-1.5 mb-4 ml-4 list-decimal">{children}</ol>
  ),
  li: ({ children }) => (
    <li className="flex gap-2 text-sm text-sentinel-text-dim">
      <span className="text-sentinel-purple mt-0.5 flex-shrink-0">›</span>
      <span className="font-body leading-relaxed">{children}</span>
    </li>
  ),
  strong: ({ children }) => (
    <strong className="text-white font-semibold">{children}</strong>
  ),
  em: ({ children }) => (
    <em className="text-sentinel-text-dim italic">{children}</em>
  ),
  // react-markdown v9+ removed the `inline` prop; use className to distinguish block vs inline
  pre: ({ children }) => (
    <pre className="bg-black/40 border border-sentinel-border rounded-lg p-4 overflow-x-auto mb-4">
      {children}
    </pre>
  ),
  code: ({ className, children }) =>
    className ? (
      // block code (fenced) — className is e.g. "language-python"
      <code className="text-sentinel-cyan font-mono text-xs">{children}</code>
    ) : (
      // inline code
      <code className="text-sentinel-cyan font-mono text-xs bg-black/40 px-1.5 py-0.5 rounded border border-sentinel-border">
        {children}
      </code>
    ),
  hr: () => <hr className="border-sentinel-border my-5" />,
  blockquote: ({ children }) => (
    <blockquote className="border-l-2 border-sentinel-purple/50 pl-4 my-3 text-sentinel-text-dim italic text-sm">
      {children}
    </blockquote>
  ),
};

export default function AgentReport({ report }) {
  const [expanded, setExpanded] = useState(true);

  if (!report) return null;

  return (
    <div
      className="mt-8 rounded-2xl border border-sentinel-purple/20 overflow-hidden"
      style={{ background: 'rgba(139,92,246,0.03)' }}
    >
      {/* Header / toggle */}
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center gap-3 px-6 py-4 hover:bg-white/[0.02] transition-colors text-left"
      >
        <div className="p-2 rounded-xl bg-sentinel-purple/10 border border-sentinel-purple/20 flex-shrink-0">
          <Bot className="w-5 h-5 text-sentinel-purple" />
        </div>
        <div className="flex-1 min-w-0">
          <h2 className="font-display text-lg font-bold text-white leading-tight">
            Intelligence Report
          </h2>
          <p className="text-sentinel-text-dim text-xs font-mono tracking-wide mt-0.5">
            OSINT Sentinel Agent — Full Threat Analysis
          </p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="hidden sm:flex items-center gap-1.5 text-xs font-mono text-sentinel-purple/70 bg-sentinel-purple/10 border border-sentinel-purple/20 px-2.5 py-1 rounded-full">
            <FileText className="w-3 h-3" />
            Agent
          </span>
          {expanded
            ? <ChevronUp className="w-4 h-4 text-sentinel-text-dim" />
            : <ChevronDown className="w-4 h-4 text-sentinel-text-dim" />}
        </div>
      </button>

      {/* Markdown body */}
      {expanded && (
        <div className="px-6 pb-6 border-t border-sentinel-purple/10">
          <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
            {report}
          </ReactMarkdown>
        </div>
      )}
    </div>
  );
}
