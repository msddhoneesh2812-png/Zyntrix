import { useEffect, useState, useRef } from 'react';
import { getGraphData } from '../services/api';
import type { GraphData } from '../types';
import { Network, ZoomIn } from 'lucide-react';

const NetworkGraph = () => {
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  
  const fetchGraph = async () => {
    try {
      const data = await getGraphData();
      setGraphData(data);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchGraph();
    const interval = setInterval(fetchGraph, 3000);
    return () => clearInterval(interval);
  }, []);

  // Simple pseudo-random layout for demo purposes since we don't have D3
  // In a real app we'd use react-force-graph or d3
  
  const renderGraph = () => {
    if (!graphData || graphData.nodes.length === 0) {
      return (
        <div className="flex-1 flex flex-col items-center justify-center text-slate-500 h-[600px]">
          <Network size={48} className="mb-4 text-slate-600" />
          <h3 className="text-xl font-medium text-slate-600 mb-2">No Relationships Available</h3>
          <p>Wait for traffic to generate graph nodes.</p>
        </div>
      );
    }

    // Sort nodes to put suspicious ones in center conceptually
    const nodes = [...graphData.nodes].sort((a, b) => b.suspicion_score - a.suspicion_score).slice(0, 100); 
    
    // Compute positions deterministically
    const nodePositions = new Map<string, { x: number, y: number }>();
    nodes.forEach(node => {
        const hash = node.id.split('').reduce((a, b) => { a = ((a << 5) - a) + b.charCodeAt(0); return a & a }, 0);
        const x = 100 + (Math.abs(hash) % 800);
        const y = 60 + (Math.abs(hash * 2) % 480);
        nodePositions.set(node.id, { x, y });
    });

    const links = graphData.links.filter(link => nodePositions.has(link.source) && nodePositions.has(link.target));

    return (
      <div className="relative w-full h-[600px] bg-slate-50 rounded-lg overflow-hidden border border-slate-200/50">
        <svg viewBox="0 0 1000 600" className="w-full h-full absolute inset-0 z-0">
          <defs>
            <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
              <polygon points="0 0, 10 3.5, 0 7" fill="#64748b" />
            </marker>
          </defs>
          {links.map((link, i) => {
            const src = nodePositions.get(link.source);
            const dst = nodePositions.get(link.target);
            if (!src || !dst) return null;
            return (
               <line 
                 key={i} 
                 x1={src.x} y1={src.y} 
                 x2={dst.x} y2={dst.y} 
                 stroke="#475569" 
                 strokeWidth={Math.min(link.value, 5)} 
                 strokeOpacity="0.5" 
                 markerEnd="url(#arrowhead)" 
               />
            );
          })}
        </svg>

        {nodes.map(node => {
          const pos = nodePositions.get(node.id)!;
          const isSuspicious = node.suspicion_score > 0;
          const size = isSuspicious ? Math.min(30 + node.suspicion_score * 10, 60) : 20;
          
          return (
            <div 
              key={node.id}
              className={`absolute rounded-full flex items-center justify-center transform -translate-x-1/2 -translate-y-1/2 cursor-pointer transition-all hover:scale-125 hover:z-10 group
                ${isSuspicious ? 'bg-cyber-critical/80 shadow-[0_0_15px_rgba(239,68,68,0.5)]' : 'bg-cyber-safe/50'}
              `}
              style={{ left: `${pos.x / 10}%`, top: `${pos.y / 6}%`, width: size, height: size }}
            >
               <div className="hidden group-hover:block absolute bottom-full mb-2 bg-slate-100 text-slate-900 text-xs px-2 py-1 rounded whitespace-nowrap z-20 border border-slate-300">
                  {node.id} <br/> Score: {node.suspicion_score.toFixed(2)}
               </div>
            </div>
          )
        })}
      </div>
    );
  };

  return (
    <div className="flex flex-col gap-6 h-full">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 mb-1">Interactive Network Graph</h1>
          <p className="text-slate-600">Relationship visualization mapped from unidirectional flows</p>
        </div>
        <div className="bg-white px-3 py-1 rounded text-sm text-slate-600 border border-slate-200 flex items-center gap-2">
          <ZoomIn size={16} />
          <span>Nodes: {graphData?.nodes.length || 0}</span>
        </div>
      </div>

      <div className="glass-panel p-6">
         <div className="flex gap-4 mb-4 text-sm">
            <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-cyber-safe/50"></div> Benign Endpoint</div>
            <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-full bg-cyber-critical/80"></div> Suspicious Endpoint (Supernode)</div>
         </div>
         {renderGraph()}
         <div className="mt-4 text-xs text-slate-500 text-center">
            * Visualization built from unidirectional observations. No reverse edges are fabricated.
         </div>
      </div>
    </div>
  );
};

export default NetworkGraph;
