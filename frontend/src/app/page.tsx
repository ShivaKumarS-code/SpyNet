'use client';

import { Shield, Activity, AlertTriangle, Network, Moon, Sun } from 'lucide-react';
import TrafficChart from '@/components/TrafficChart';
import AlertsTable from '@/components/AlertsTable';
import StatsCards from '@/components/StatsCards';
import TopTalkers from '@/components/TopTalkers';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useTheme } from '@/hooks/useTheme';

export default function Dashboard() {
  const { isDark, toggleTheme } = useTheme();
  const { 
    trafficData, 
    alerts, 
    stats, 
    topTalkers, 
    isConnected 
  } = useWebSocket('ws://localhost:8000/ws');

  return (
    <div className={`min-h-screen transition-colors duration-200 ${
      isDark ? 'dark bg-gray-900' : 'bg-gray-50'
    }`}>
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-600 dark:text-blue-400" />
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                SpyNet Dashboard
              </h1>
              <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-sm ${
                isConnected 
                  ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' 
                  : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
              }`}>
                <div className={`w-2 h-2 rounded-full ${
                  isConnected ? 'bg-green-500' : 'bg-red-500'
                }`} />
                {isConnected ? 'Connected' : 'Disconnected'}
              </div>
            </div>
            
            <button
              onClick={toggleTheme}
              className="p-2 rounded-lg bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 transition-colors"
              aria-label="Toggle theme"
            >
              {isDark ? (
                <Sun className="h-5 w-5 text-yellow-500" />
              ) : (
                <Moon className="h-5 w-5 text-gray-600" />
              )}
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="space-y-8">
          {/* Stats Cards */}
          <StatsCards stats={stats} />

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Traffic Chart */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
              <div className="flex items-center space-x-2 mb-4">
                <Activity className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Network Traffic
                </h2>
              </div>
              <TrafficChart data={trafficData} />
            </div>

            {/* Top Talkers */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
              <div className="flex items-center space-x-2 mb-4">
                <Network className="h-5 w-5 text-green-600 dark:text-green-400" />
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Top Talkers
                </h2>
              </div>
              <TopTalkers data={topTalkers} />
            </div>
          </div>

          {/* Alerts Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center space-x-2 mb-4">
              <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400" />
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
                Security Alerts
              </h2>
            </div>
            <AlertsTable alerts={alerts} />
          </div>
        </div>
      </main>
    </div>
  );
}
