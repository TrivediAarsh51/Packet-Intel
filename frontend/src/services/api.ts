import axios from 'axios';

const API_URL = (import.meta as any).env?.VITE_API_URL || 'http://localhost:8000/api';

// Create axios instance
export const api = axios.create({
  baseURL: API_URL,
});

// Request interceptor to attach JWT token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Auth Services
export const authService = {
  async signup(username: string, email: string, password: string) {
    const response = await api.post('/auth/signup', { username, email, password });
    if (response.data.access_token) {
      localStorage.setItem('token', response.data.access_token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
    }
    return response.data;
  },

  async login(username: string, password: string) {
    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password);
    
    const response = await api.post('/auth/login', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    if (response.data.access_token) {
      localStorage.setItem('token', response.data.access_token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
    }
    return response.data;
  },

  async getMe() {
    const response = await api.get('/auth/me');
    return response.data;
  },

  logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  },

  isAuthenticated() {
    return !!localStorage.getItem('token');
  },

  getCurrentUser() {
    const userStr = localStorage.getItem('user');
    if (userStr) {
      try {
        return JSON.parse(userStr);
      } catch (e) {
        return null;
      }
    }
    return null;
  },

  async createUser(username: string, email: string, role: string) {
    const response = await api.post('/auth/create-user', { username, email, role });
    return response.data;
  }
};

// Packets & Capture Services
export const packetService = {
  async uploadPcap(file: File) {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post('/packets/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  async getSessions() {
    const response = await api.get('/packets/sessions');
    return response.data;
  },

  async getSession(sessionId: number) {
    const response = await api.get(`/packets/sessions/${sessionId}`);
    return response.data;
  },

  async deleteSession(sessionId: number) {
    const response = await api.delete(`/packets/sessions/${sessionId}`);
    return response.data;
  },

  async getPackets(sessionId: number, skip = 0, limit = 100, filters: { srcIp?: string; dstIp?: string; protocol?: string } = {}) {
    const params: any = { skip, limit };
    if (filters.srcIp) params.src_ip = filters.srcIp;
    if (filters.dstIp) params.dst_ip = filters.dstIp;
    if (filters.protocol) params.protocol = filters.protocol;
    
    const response = await api.get(`/packets/packets/${sessionId}`, { params });
    return response.data;
  },

  async getPacketsCount(sessionId: number, filters: { srcIp?: string; dstIp?: string; protocol?: string } = {}) {
    const params: any = {};
    if (filters.srcIp) params.src_ip = filters.srcIp;
    if (filters.dstIp) params.dst_ip = filters.dstIp;
    if (filters.protocol) params.protocol = filters.protocol;
    
    const response = await api.get(`/packets/packets/${sessionId}/count`, { params });
    return response.data;
  },

  async getFlows(sessionId: number) {
    const response = await api.get(`/packets/flows/${sessionId}`);
    return response.data;
  },

  async getAlerts(sessionId?: number, severity?: string, limit = 50) {
    const params: any = { limit };
    if (sessionId) params.session_id = sessionId;
    if (severity) params.severity = severity;
    
    const response = await api.get('/packets/alerts', { params });
    return response.data;
  },

  async acknowledgeAlert(alertId: number) {
    const response = await api.patch(`/packets/alerts/${alertId}/acknowledge`);
    return response.data;
  },

  async getDashboardStats(sessionId?: number) {
    const params: any = {};
    if (sessionId) params.session_id = sessionId;
    const response = await api.get('/packets/stats/dashboard', { params });
    return response.data;
  },

  async getInterfaces() {
    const response = await api.get('/packets/interfaces');
    return response.data;
  },

  async startLiveCapture(interfaceId: string, name?: string, description?: string) {
    const params: any = { interface: interfaceId };
    if (name) params.name = name;
    if (description) params.description = description;
    const response = await api.post('/packets/live/start', null, { params });
    return response.data;
  },

  async stopLiveCapture(sessionId: number) {
    const response = await api.post(`/packets/live/stop/${sessionId}`);
    return response.data;
  }
};

