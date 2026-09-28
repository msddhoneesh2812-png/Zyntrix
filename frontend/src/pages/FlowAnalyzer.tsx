import { useState, useRef } from 'react';
import { Search, Upload, FileJson } from 'lucide-react';
import { analyzeFlow, uploadFlows } from '../services/api';
import type { AnalyzeResponse } from '../types';
import type { FlowRecord } from '../types';

const FlowAnalyzer = () => {
  const [jsonInput, setJsonInput] = useState('');
  const [analysisResult, setAnalysisResult] = useState<AnalyzeResponse | null>(null);
  const [error, setError] = useState('');
  const [uploadMessage, setUploadMessage] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleAnalyze = async () => {
    try {
      setError('');
      setAnalysisResult(null);
      setIsAnalyzing(true);
      const flow: FlowRecord = JSON.parse(jsonInput);
      const result = await analyzeFlow(flow);
      setAnalysisResult(result);
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Invalid JSON or API error';
      setError(message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    
    try {
      setUploadMessage('Uploading...');
      const result = await uploadFlows(file);
      setUploadMessage(`Success: ${result.parsed_records} records parsed. Errors: ${result.errors}`);
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Upload failed';
      setUploadMessage(`Upload failed: ${message}`);
    }
    
    if (fileInputRef.current) {
        fileInputRef.current.value = '';
    }
  };

  const getThreatColor = (classification?: string) => {
    switch (classification) {
      case 'MALICIOUS': return 'text-cyber-critical';
      case 'OUTLIER': return 'text-cyber-warning';
      case 'BENIGN': return 'text-cyber-safe';
      default: return 'text-slate-600';
    }
  };

  return (
    <div className="flex flex-col gap-6 h-full">
      <div>
        <h1 className="text-2xl font-bold text-slate-900 mb-1">Flow Analyzer</h1>
        <p className="text-slate-600">Manual inspection of individual unidirectional flows</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div 
          className="glass-panel p-6 flex flex-col items-center justify-center min-h-[400px] border-dashed border-2 border-slate-300 hover:border-cyber-info hover:shadow-[0_0_30px_rgba(59,130,246,0.15)] transition-all duration-300 cursor-pointer group"
          onClick={() => fileInputRef.current?.click()}
          role="button"
          tabIndex={0}
          aria-label="Upload flow data file"
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click(); }}
        >
           <input type="file" ref={fileInputRef} className="hidden" accept=".json" onChange={handleFileUpload} aria-hidden="true" />
           <Upload size={48} className="text-slate-500 group-hover:text-cyber-info mb-4 transition-colors" />
           <h3 className="text-xl font-medium text-slate-900 mb-2">Upload Flow Data</h3>
           <p className="text-slate-600 text-center mb-6">Click to select a JSON file containing unidirectional flow records</p>
           <button className="btn-primary" onClick={(e) => { e.stopPropagation(); fileInputRef.current?.click(); }}>Browse Files</button>
           {uploadMessage && <p className="mt-4 text-cyber-info text-center" role="status">{uploadMessage}</p>}
        </div>

        <div className="glass-panel p-6 flex flex-col">
           <h3 className="text-lg font-medium text-slate-900 mb-4 flex items-center gap-2">
             <FileJson size={20} className="text-cyber-info" /> Paste Flow Record
           </h3>
           <label htmlFor="flow-json-input" className="sr-only">Flow record JSON</label>
           <textarea 
             id="flow-json-input"
             className="flex-1 bg-slate-50 border border-slate-200 rounded-lg p-4 font-mono text-sm text-slate-700 resize-none focus:outline-none focus:border-cyber-info focus:shadow-[0_0_15px_rgba(59,130,246,0.2)] transition-all duration-300"
             placeholder='{ "src_ip": "...", "dst_port": 443, ... }'
             value={jsonInput}
             onChange={(e) => setJsonInput(e.target.value)}
           />
           {error && <p className="text-red-500 mt-2 text-sm" role="alert">{error}</p>}
           <button
             className="btn-primary mt-4 w-full"
             onClick={handleAnalyze}
             disabled={isAnalyzing || !jsonInput.trim()}
           >
             {isAnalyzing ? 'Analyzing...' : 'Analyze Flow'}
           </button>
        </div>
      </div>
      
      <div className={`glass-panel p-6 transition-all duration-500 transform ${analysisResult ? 'opacity-100 translate-y-0 shadow-[0_10px_40px_-10px_rgba(59,130,246,0.2)]' : 'opacity-50 pointer-events-none translate-y-4'}`}>
         <h3 className="text-lg font-medium text-slate-900 mb-4 flex items-center gap-2">
            <Search size={20} className="text-slate-600" /> Analysis Results
         </h3>
         {!analysisResult ? (
           <p className="text-slate-500">Upload or paste a flow record to view extracted features and model predictions.</p>
         ) : (
           <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
             <div className="col-span-1">
               <h4 className="text-sm font-semibold text-slate-600 mb-2 uppercase tracking-wider">Classification</h4>
               <div className={`text-2xl font-bold mb-1 ${getThreatColor(analysisResult.classification)}`}>{analysisResult.classification}</div>
               <div className="text-slate-700 mb-1">Detection Score: {(analysisResult.detection_score * 100).toFixed(1)}%</div>
               <div className="text-slate-700">Severity: {analysisResult.severity}</div>
               {analysisResult.threat_type && <div className="text-slate-700 mt-2 text-sm bg-slate-100 p-2 rounded">Type: {analysisResult.threat_type}</div>}
             </div>
             
             <div className="col-span-2">
               <h4 className="text-sm font-semibold text-slate-600 mb-2 uppercase tracking-wider">Detection Reasons</h4>
               <ul className="list-disc list-inside space-y-1">
                 {analysisResult.reasons.map((r: string, i: number) => (
                   <li key={i} className="text-slate-700">{r}</li>
                 ))}
               </ul>
             </div>
           </div>
         )}
      </div>
    </div>
  );
};

export default FlowAnalyzer;
