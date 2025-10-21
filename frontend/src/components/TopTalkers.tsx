'use client';

interface TopTalker {
  ip: string;
  packets: number;
  bytes: number;
}

interface TopTalkersProps {
  data: TopTalker[];
}

export default function TopTalkers({ data }: TopTalkersProps) {
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const formatNumber = (num: number): string => {
    return num.toLocaleString();
  };

  const maxBytes = Math.max(...data.map(item => item.bytes));

  return (
    <div className="space-y-4">
      {data.length > 0 ? (
        data.map((talker, index) => {
          const percentage = (talker.bytes / maxBytes) * 100;
          
          return (
            <div key={talker.ip} className="space-y-2">
              <div className="flex justify-between items-center">
                <div className="flex items-center space-x-3">
                  <span className="flex items-center justify-center w-6 h-6 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded-full text-xs font-medium">
                    {index + 1}
                  </span>
                  <span className="font-mono text-sm text-gray-900 dark:text-white">
                    {talker.ip}
                  </span>
                </div>
                <div className="text-right">
                  <div className="text-sm font-medium text-gray-900 dark:text-white">
                    {formatBytes(talker.bytes)}
                  </div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">
                    {formatNumber(talker.packets)} packets
                  </div>
                </div>
              </div>
              
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div
                  className="bg-blue-600 dark:bg-blue-400 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${percentage}%` }}
                />
              </div>
            </div>
          );
        })
      ) : (
        <div className="flex items-center justify-center h-32">
          <div className="text-center">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600 mx-auto mb-2"></div>
            <p className="text-sm text-gray-500 dark:text-gray-400">Loading top talkers...</p>
          </div>
        </div>
      )}
    </div>
  );
}