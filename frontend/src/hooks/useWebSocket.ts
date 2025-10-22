'use client';

import { useState, useEffect, useRef } from 'react';

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
  
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    // Convert HTTP URL to WebSocket URL
    const wsUrl = url.replace('http://', 'ws://').replace('https://', 'wss://') + '/ws/realtime';
    console.log('Attempting to connect to WebSocket:', wsUrl);
    
    // Initialize WebSocket connection
    try {
      socketRef.current = new WebSocket(wsUrl);
    } catch (error) {
      console.error('Failed to create WebSocket:', error);
      return;
    }

    const socket = socketRef.current;

    socket.onopen = () => {
      setIsConnected(true);
      console.log('✅ Connected to SpyNet backend via WebSocket');
      
      // Send subscription request
      try {
        socket.send(JSON.stringify({
          type: 'subscribe',
          data_types: ['alerts', 'traffic', 'connections', 'stats']
        }));
        console.log('📡 Sent subscription request');
      } catch (error) {
        console.error('Failed to send subscription:', error);
      }
      
      // Fetch initial data from API
      fetchInitialData();
    };
    
    const fetchInitialData = async () => {
      try {
        // Use the base URL directly since url is already the base URL
        const baseUrl = url;
        console.log('🔗 Fetching initial data from:', baseUrl);
        
        // Fetch traffic stats
        const trafficResponse = await fetch(`${baseUrl}/api/v1/traffic/stats?hours=1`);
        if (trafficResponse.ok) {
          const trafficData = await trafficResponse.json();
          console.log('📊 Initial traffic data:', trafficData);
          
          setStats(prev => ({
            ...prev,
            totalPackets: trafficData.total_packets || 0,
            totalBytes: trafficData.total_bytes || 0
          }));
          
          if (trafficData.top_sources) {
            const talkers = trafficData.top_sources.map((source: any) => ({
              ip: source.ip,
              packets: source.packet_count,
              bytes: source.total_bytes
            }));
            setTopTalkers(talkers);
          }
        }
        
        // Fetch alerts
        const alertsResponse = await fetch(`${baseUrl}/api/v1/alerts?limit=10`);
        if (alertsResponse.ok) {
          const alertsData = await alertsResponse.json();
          console.log('🚨 Initial alerts data:', alertsData);
          
          const formattedAlerts = alertsData.map((alert: any) => ({
            id: alert.id.toString(),
            timestamp: alert.timestamp,
            type: alert.alert_type,
            severity: alert.severity,
            source_ip: alert.source_ip,
            description: alert.description
          }));
          
          setAlerts(formattedAlerts);
          setStats(prev => ({
            ...prev,
            alertsCount: alertsData.length
          }));
        }
        
        // Fetch active connections
        const connectionsResponse = await fetch(`${baseUrl}/api/v1/connections/active?limit=100`);
        if (connectionsResponse.ok) {
          const connectionsData = await connectionsResponse.json();
          console.log('🔗 Initial connections data:', connectionsData);
          
          setStats(prev => ({
            ...prev,
            activeConnections: connectionsData.length
          }));
        }
        
      } catch (error) {
        console.error('Error fetching initial data:', error);
      }
    };

    socket.onclose = (event) => {
      setIsConnected(false);
      console.log('❌ Disconnected from SpyNet backend. Code:', event.code, 'Reason:', event.reason);
    };

    socket.onerror = (error) => {
      console.error('🚨 WebSocket error:', error);
      console.error('WebSocket URL was:', wsUrl);
      setIsConnected(false);
    };

    socket.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        
        switch (message.type) {
          case 'traffic_stats':
            if (message.data) {
              console.log('📊 Received traffic stats:', message.data);
              // Convert backend traffic stats to frontend format
              const now = new Date().toISOString();
              const trafficPoint = {
                timestamp: now,
                packets: message.data.total_packets || 0,
                bytes: message.data.total_bytes || 0
              };
              setTrafficData(prev => {
                const newData = [...prev, trafficPoint];
                return newData.slice(-50);
              });
              
              // Update stats from traffic data
              setStats(prev => ({
                ...prev,
                totalPackets: message.data.total_packets || 0,
                totalBytes: message.data.total_bytes || 0
              }));
              
              // Update top talkers
              if (message.data.top_sources) {
                const talkers = message.data.top_sources.map((source: any) => ({
                  ip: source.ip,
                  packets: source.packet_count,
                  bytes: source.total_bytes
                }));
                setTopTalkers(talkers);
              }
            }
            break;
            
          case 'traffic_update':
            if (message.data) {
              console.log('📊 Received traffic update:', message.data);
              setTrafficData(prev => {
                const newData = [...prev, message.data];
                return newData.slice(-50);
              });
            }
            break;
            
          case 'alert_count':
            if (message.data) {
              setStats(prev => ({
                ...prev,
                alertsCount: message.data.unresolved_count || 0
              }));
            }
            break;
            
          case 'new_alert':
            if (message.data) {
              setAlerts(prev => [message.data, ...prev.slice(0, 99)]);
            }
            break;
            
          case 'stats_update':
            if (message.data) {
              setStats(message.data);
            }
            break;
            
          case 'top_talkers_update':
            if (message.data) {
              setTopTalkers(message.data);
            }
            break;
            
          case 'welcome':
            console.log('WebSocket welcome:', message.message);
            break;
            
          case 'subscription_confirmed':
            console.log('📡 Subscription confirmed:', message.data_types);
            break;
            
          default:
            console.log('Unknown message type:', message.type, message);
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error);
      }
    };

    // Cleanup on unmount
    return () => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.close();
      }
    };
  }, [url]);

  // Generate sample data for immediate testing
  useEffect(() => {
    // Always show some sample data initially for testing
    const now = new Date();
    const sampleTrafficData = Array.from({ length: 10 }, (_, i) => ({
      timestamp: new Date(now.getTime() - (9 - i) * 60000).toISOString(),
      packets: Math.floor(Math.random() * 100) + 50,
      bytes: Math.floor(Math.random() * 50000) + 10000
    }));
    
    setTrafficData(sampleTrafficData);
    setStats({
      totalPackets: 1250,
      totalBytes: 2500000,
      activeConnections: 45,
      alertsCount: 3
    });
    setTopTalkers([
      { ip: '192.168.1.100', packets: 450, bytes: 890000 },
      { ip: '192.168.1.101', packets: 320, bytes: 650000 },
      { ip: '192.168.1.102', packets: 280, bytes: 520000 }
    ]);
    
    // Add some sample alerts
    setAlerts([
      {
        id: '1',
        timestamp: new Date().toISOString(),
        type: 'Port Scan',
        severity: 'High',
        source_ip: '203.0.113.10',
        description: 'Port scan detected from external IP'
      },
      {
        id: '2',
        timestamp: new Date(Date.now() - 300000).toISOString(),
        type: 'DDoS Attack',
        severity: 'Critical',
        source_ip: '198.51.100.25',
        description: 'Potential DDoS attack detected'
      }
    ]);
  }, []); // Run once on mount

  return {
    isConnected,
    trafficData,
    alerts,
    stats,
    topTalkers
  };
}