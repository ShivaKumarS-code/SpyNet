'use client';

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface TrafficData {
  timestamp: string;
  packets: number;
  bytes: number;
}

interface TrafficChartProps {
  data: TrafficData[];
}

export default function TrafficChart({ data }: TrafficChartProps) {
  // Format data for the chart
  const chartData = data.map(item => ({
    time: new Date(item.timestamp).toLocaleTimeString('en-US', { 
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    }),
    packets: item.packets,
    bytes: Math.round(item.bytes / 1024) // Convert to KB for better readability
  }));

  const CustomTooltip = ({ active, payload, label }: { 
    active?: boolean; 
    payload?: Array<{ value: number; color: string }>; 
    label?: string 
  }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white dark:bg-gray-800 p-3 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg">
          <p className="text-sm font-medium text-gray-900 dark:text-white">{`Time: ${label}`}</p>
          <p className="text-sm text-blue-600 dark:text-blue-400">
            {`Packets: ${payload[0].value.toLocaleString()}`}
          </p>
          <p className="text-sm text-green-600 dark:text-green-400">
            {`Bytes: ${payload[1].value.toLocaleString()} KB`}
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="h-80">
      {chartData.length > 0 ? (
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chartData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" className="stroke-gray-200 dark:stroke-gray-700" />
            <XAxis 
              dataKey="time" 
              className="text-gray-600 dark:text-gray-400"
              tick={{ fontSize: 12 }}
            />
            <YAxis 
              yAxisId="packets"
              orientation="left"
              className="text-gray-600 dark:text-gray-400"
              tick={{ fontSize: 12 }}
            />
            <YAxis 
              yAxisId="bytes"
              orientation="right"
              className="text-gray-600 dark:text-gray-400"
              tick={{ fontSize: 12 }}
            />
            <Tooltip content={<CustomTooltip />} />
            <Line
              yAxisId="packets"
              type="monotone"
              dataKey="packets"
              stroke="#3B82F6"
              strokeWidth={2}
              dot={false}
              name="Packets"
            />
            <Line
              yAxisId="bytes"
              type="monotone"
              dataKey="bytes"
              stroke="#10B981"
              strokeWidth={2}
              dot={false}
              name="Bytes (KB)"
            />
          </LineChart>
        </ResponsiveContainer>
      ) : (
        <div className="flex items-center justify-center h-full">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
            <p className="text-gray-500 dark:text-gray-400">Loading traffic data...</p>
          </div>
        </div>
      )}
    </div>
  );
}