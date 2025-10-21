/**
 * API configuration for SpyNet frontend
 */

export const API_CONFIG = {
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000',
  wsURL: process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000',
  timeout: 10000,
  retryAttempts: 3,
} as const;

export const APP_CONFIG = {
  name: process.env.NEXT_PUBLIC_APP_NAME || 'SpyNet',
  version: process.env.NEXT_PUBLIC_APP_VERSION || '1.0.0',
  features: {
    darkMode: process.env.NEXT_PUBLIC_ENABLE_DARK_MODE === 'true',
    notifications: process.env.NEXT_PUBLIC_ENABLE_NOTIFICATIONS === 'true',
    realTime: process.env.NEXT_PUBLIC_ENABLE_REAL_TIME === 'true',
  },
} as const;

export const CHART_CONFIG = {
  refreshInterval: parseInt(process.env.NEXT_PUBLIC_CHART_REFRESH_INTERVAL || '5000'),
  maxDataPoints: parseInt(process.env.NEXT_PUBLIC_MAX_CHART_POINTS || '100'),
} as const;

export const ALERT_CONFIG = {
  refreshInterval: parseInt(process.env.NEXT_PUBLIC_ALERT_REFRESH_INTERVAL || '3000'),
  maxDisplayCount: parseInt(process.env.NEXT_PUBLIC_MAX_ALERTS_DISPLAY || '50'),
} as const;