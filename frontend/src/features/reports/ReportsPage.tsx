import React from 'react';
import { useCapture } from '../../context/CaptureContext';
import { api } from '../../lib/api';
import { EmptyState } from '../../components/EmptyState';
import {
  FileText,
  FileCode,
  Download,
  ExternalLink,
  CheckCircle2,
  Printer
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export const ReportsPage: React.FC = () => {
  const { activeCapture } = useCapture();
  const navigate = useNavigate();

  if (!activeCapture) {
    return (
      <EmptyState
        title="No Capture Selected"
        description="Select or upload a capture to generate standalone HTML, PDF, or JSON diagnostic reports."
        actionText="Go to Captures"
        onAction={() => navigate('/captures')}
      />
    );
  }

  const htmlUrl = api.getReportUrl(activeCapture.id, 'html');
  const pdfUrl = api.getReportUrl(activeCapture.id, 'pdf');
  const jsonUrl = api.getReportUrl(activeCapture.id, 'json');

  return (
    <div className="space-y-8 max-w-4xl mx-auto animate-in fade-in duration-200">
      {/* Title */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Reports & Export</h1>
        <p className="text-xs text-slate-400 font-mono mt-1">
          Export self-contained, evidence-backed diagnostic reports for {activeCapture.original_filename}
        </p>
      </div>

      {/* Overview Note */}
      <div className="p-4 bg-slate-900/60 border-l-4 border-cyan-500 rounded-r-xl text-xs text-slate-300 space-y-1">
        <span className="font-semibold text-cyan-400 text-sm block">Authenticity & Offline Guarantee</span>
        <p>
          All generated reports reflect exact frame counts, sequence metadata, and heuristic rules computed directly from the uploaded capture. Raw payloads are sanitized to prevent cross-site scripting and avoid unauthorized data leakage.
        </p>
      </div>

      {/* Reports Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* HTML Report */}
        <div className="p-6 bg-slate-900/70 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4 hover:border-slate-700 transition-colors">
          <div className="space-y-3">
            <div className="p-3 w-12 h-12 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center">
              <FileText className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-slate-100">Interactive HTML</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Standalone, responsive HTML report containing dark-themed dashboards, protocol tables, and finding summaries.
            </p>
          </div>

          <div className="pt-4 border-t border-slate-800 space-y-2">
            <a
              href={htmlUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="w-full py-2 px-3 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold text-xs rounded-lg flex items-center justify-center gap-1.5 transition-colors shadow-sm"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>Open in New Tab</span>
            </a>
            <a
              href={htmlUrl}
              download={`nettrace_report_${activeCapture.original_filename}.html`}
              className="w-full py-2 px-3 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-lg flex items-center justify-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download HTML</span>
            </a>
          </div>
        </div>

        {/* PDF Report */}
        <div className="p-6 bg-slate-900/70 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4 hover:border-slate-700 transition-colors">
          <div className="space-y-3">
            <div className="p-3 w-12 h-12 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center">
              <Printer className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-slate-100">Executive PDF</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Formatted multi-page document rendered via ReportLab with tables, finding breakdowns, and page numbering.
            </p>
          </div>

          <div className="pt-4 border-t border-slate-800">
            <a
              href={pdfUrl}
              download={`nettrace_report_${activeCapture.original_filename}.pdf`}
              className="w-full py-2.5 px-3 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-xs rounded-lg flex items-center justify-center gap-1.5 transition-colors shadow-sm"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download PDF</span>
            </a>
          </div>
        </div>

        {/* JSON Schema Export */}
        <div className="p-6 bg-slate-900/70 border border-slate-800 rounded-xl flex flex-col justify-between space-y-4 hover:border-slate-700 transition-colors">
          <div className="space-y-3">
            <div className="p-3 w-12 h-12 rounded-lg bg-blue-500/10 text-blue-400 flex items-center justify-center">
              <FileCode className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-slate-100">Structured JSON</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Machine-readable versioned export of all capture metadata, conversation streams, DNS records, and evidence packet numbers.
            </p>
          </div>

          <div className="pt-4 border-t border-slate-800">
            <a
              href={jsonUrl}
              download={`nettrace_export_${activeCapture.original_filename}.json`}
              className="w-full py-2.5 px-3 bg-blue-600 hover:bg-blue-500 text-slate-950 font-semibold text-xs rounded-lg flex items-center justify-center gap-1.5 transition-colors shadow-sm"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </a>
          </div>
        </div>
      </div>

      {/* Included Sections Checkmarks */}
      <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
        <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
          Included Report Sections
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400" />
            <span>Capture Metadata (Frames, Wire length, Duration)</span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400" />
            <span>Protocol Distribution & Frame Count Breakdown</span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400" />
            <span>Top Communicating Endpoints & Traffic Volumes</span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400" />
            <span>Active TCP Conversations & Handshake States</span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400" />
            <span>DNS Resolution Performance & Response Codes</span>
          </div>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-400" />
            <span>Evidence-Linked Findings with Explanations & Caveats</span>
          </div>
        </div>
      </div>
    </div>
  );
};
