import axios from 'axios';
import type { FlowRecord, Alert, EvidenceRecord, SystemStatus, GraphData, Stats } from '../types';
import type { AnalyzeResponse } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15_000,   // 15s timeout — prevents hanging requests
});

// ---------------------------------------------------------------------------
// Centralized error interceptor — strips verbose stack traces from logs
// ---------------------------------------------------------------------------
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    const detail = error.response?.data?.detail;

    if (status === 429) {
      console.warn('Rate limited — slow down requests');
    } else if (status && status >= 500) {
      console.error(`Server error (${status}):`, detail || 'Unknown');
    }

    return Promise.reject(error);
  },
);

// ---------------------------------------------------------------------------
// API Functions
// ---------------------------------------------------------------------------

export const getHealth = async (): Promise<{ status: string }> => {
  const response = await api.get('/health');
  return response.data;
};

export const getStats = async (): Promise<Stats> => {
  const response = await api.get('/stats');
  return response.data;
};

export const getSystemStatus = async (): Promise<SystemStatus> => {
  const response = await api.get('/system/status');
  return response.data;
};

export const getFlows = async (): Promise<FlowRecord[]> => {
  const response = await api.get('/flows');
  return response.data;
};

export const getAlerts = async (): Promise<Alert[]> => {
  const response = await api.get('/alerts');
  return response.data;
};

export const getAlert = async (id: string): Promise<Alert> => {
  const response = await api.get(`/alerts/${encodeURIComponent(id)}`);
  return response.data;
};

export const getGraphData = async (): Promise<GraphData> => {
  const response = await api.get('/graph');
  return response.data;
};

export const getEvidence = async (): Promise<EvidenceRecord[]> => {
  const response = await api.get('/evidence');
  return response.data;
};

export const verifyEvidence = async (alertId: string): Promise<{ verified: boolean; hash: string }> => {
  const response = await api.post(`/evidence/verify?alert_id=${encodeURIComponent(alertId)}`);
  return response.data;
};

export const startDemo = async (): Promise<{ status: string }> => {
  const response = await api.post('/demo/start');
  return response.data;
};

export const stopDemo = async (): Promise<{ status: string }> => {
  const response = await api.post('/demo/stop');
  return response.data;
};

export const resetSystem = async (): Promise<{ status: string }> => {
  const response = await api.post('/reset');
  return response.data;
};

export const injectFlow = async (flow: FlowRecord): Promise<{ status: string }> => {
  const response = await api.post('/demo/inject', { flow });
  return response.data;
};

export const analyzeFlow = async (flow: FlowRecord): Promise<AnalyzeResponse> => {
  const response = await api.post('/flows/analyze', { flow });
  return response.data;
};

export const uploadFlows = async (file: File): Promise<{ parsed_records: number; errors: number; message: string }> => {
  const formData = new FormData();
  formData.append('file', file);
  const response = await api.post('/flows/upload', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
};
