'use client';

import { useState, useEffect, useRef } from 'react';
import { io, Socket } from 'socket.io-client';

interface TrafficData {
  timestamp: string;
  packets: number;
  bytes: number;
}

interface Alert {
  id: string;
  timestamp: string;
  type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  source_ip: string;
  description: string;
}

interface Stats {
  totalPackets: number;
  totalBytes: number;
  activeConnections: number;
  alertsCount: number;
}

interface TopTalker {
  ip: string;
  packets: number;
  bytes: number;
}

export function useWebSocket(url: string) {
  const [isConnected, setIsConnected] = useState(false);
  const [trafficData, setTrafficData] = useState<TrafficData[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<Stats>({
    totalPackets: 0,
    totalBytes: 0,
    activeConnections: 0,
    alertsCount: 0
  });
  const [topTalkers, setTopTalkers] = useState<TopTalker[]>([]);
  
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    // Initialize socket connection
    socketRef.current = io(url, {
      transports: ['websocket'],
      autoConnect: true
    });

    const socket = socketRef.current;

    socket.on('connect', () => {
      setIsConnected(true);
      console.log('Connected to SpyNet backend');
    });

    socket.on('disconnect', () => {
      setIsConnected(false);
      console.log('Disconnected from SpyNet backend');
    });

    socket.on('traffic_update', (data: TrafficData) => {
      setTrafficData(prev => {
        const newData = [...prev, data];
        // Keep only last 50 data points for performance
        return newData.slice(-50);
      });
    });

    socket.on('new_alert', (alert: Alert) => {
      setAlerts(prev => [alert, ...prev.slice(0, 99)]); // Keep last 100 alerts
    });

    socket.on('stats_update', (newStats: Stats) => {
      setStats(newStats);
    });

    socket.on('top_talkers_update', (talkers: TopTalker[]) => {
      setTopTalkers(talkers);
    });

    // Cleanup on unmount
    return () => {
      socket.disconnect();
    };
  }, [url]);

  // Generate mock data for development when not connected
  useEffect(() => {
    if (!isConnected) {
      const interval = setInterval(() => {
        // Mock traffic data
        const mockTrafficData: TrafficData = {
          timestamp: new Date().toISOString(),
          packets: Math.floor(Math.random() * 1000) + 100,
          bytes: Math.floor(Math.random() * 100000) + 10000
        };
        
        setTrafficData(prev => {
          const newData = [...prev, mockTrafficData];
          return newData.slice(-50);
        });

        // Mock stats
        setStats({
          totalPackets: Math.floor(Math.random() * 100000) + 50000,
          totalBytes: Math.floor(Math.random() * 10000000) + 5000000,
          activeConnections: Math.floor(Math.random() * 500) + 100,
          alertsCount: Math.floor(Math.random() * 50) + 10
        });

        // Mock top talkers
        setTopTalkers([
          { ip: '192.168.1.100', packets: 15420, bytes: 2340000 },
          { ip: '10.0.0.50', packets: 12300, bytes: 1890000 },
          { ip: '172.16.0.25', packets: 9800, bytes: 1560000 },
          { ip: '192.168.1.200', packets: 7650, bytes: 1230000 },
          { ip: '10.0.0.75', packets: 6540, bytes: 980000 }
        ]);

        // Occasionally add mock alerts
        if (Math.random() < 0.1) {
          const severities: Alert['severity'][] = ['Low', 'Medium', 'High', 'Critical'];
          const types = ['Port Scan', 'DDoS Attack', 'Suspicious Payload', 'Anomaly Detected'];
          
          const mockAlert: Alert = {
            id: Math.random().toString(36).substr(2, 9),
            timestamp: new Date().toISOString(),
            type: types[Math.floor(Math.random() * types.length)],
            severity: severities[Math.floor(Math.random() * severities.length)],
            source_ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
            description: 'Mock alert for development testing'
          };
          
          setAlerts(prev => [mockAlert, ...prev.slice(0, 99)]);
        }
      }, 2000);

      return () => clearInterval(interval);
    }
  }, [isConnected]);

  return {
    isConnected,
    trafficData,
    alerts,
    stats,
    topTalkers
  };
}