export interface FlowRecord {
  id: string;
  timestamp: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  packets: number;
  bytes: number;
  duration: number;
  mean_iat: number;
  mean_packet_size: number;
  status: string;
  threat_class?: string;
  detection_score?: number;
  severity?: string;
  threat_type?: string;
}

export interface Alert {
  id: string;
  flow_id: string;
  timestamp: string;
  classification: string;
  detection_score: number;
  severity: string;
  reasons: string[];
  evidence_hash: string;
  src_ip: string;
  dst_ip: string;
  protocol: string;
  threat_type?: string;
}

export interface EvidenceRecord {
  id: string;
  alert_id: string;
  timestamp: string;
  previous_hash: string;
  current_hash: string;
  alert_classification: string;
}

export interface SystemStatus {
  flow_ingestion: string;
  feature_extraction: string;
  detection_engine: string;
  graph_engine: string;
  alert_engine: string;
  evidence_ledger: string;
  mode: string;
}

export interface GraphNode {
  id: string;
  group: number;
  suspicion_score: number;
}

export interface GraphLink {
  source: string;
  target: string;
  value: number;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

export interface Stats {
  flows_processed: number;
  suspicious_flows: number;
  malicious_flows: number;
  active_alerts: number;
  is_running: boolean;
  history?: Array<{
    time: string;
    benign: number;
    suspicious: number;
    malicious: number;
  }>;
}

export interface AnalyzeResponse {
  classification: string;
  detection_score: number;
  severity: string;
  threat_type: string | null;
  reasons: string[];
  features: Record<string, string | number>;
}
