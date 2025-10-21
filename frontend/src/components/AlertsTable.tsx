'use client';

import { useState, useMemo } from 'react';
import { Search, Filter, ChevronDown, ChevronUp } from 'lucide-react';

interface Alert {
  id: string;
  timestamp: string;
  type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  source_ip: string;
  description: string;
}

interface AlertsTableProps {
  alerts: Alert[];
}

type SortField = 'timestamp' | 'severity' | 'type' | 'source_ip';
type SortDirection = 'asc' | 'desc';

export default function AlertsTable({ alerts }: AlertsTableProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<SortField>('timestamp');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [showFilters, setShowFilters] = useState(false);

  const severityColors = {
    Low: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
    Medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
    High: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
    Critical: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
  };

  const filteredAndSortedAlerts = useMemo(() => {
    const severityOrder = { Low: 1, Medium: 2, High: 3, Critical: 4 };
    const filtered = alerts.filter(alert => {
      const matchesSearch = 
        alert.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
        alert.source_ip.includes(searchTerm) ||
        alert.description.toLowerCase().includes(searchTerm.toLowerCase());
      
      const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter;
      
      return matchesSearch && matchesSeverity;
    });

    return filtered.sort((a, b) => {
      let aValue: string | number = a[sortField];
      let bValue: string | number = b[sortField];

      if (sortField === 'timestamp') {
        aValue = new Date(aValue).getTime();
        bValue = new Date(bValue).getTime();
      } else if (sortField === 'severity') {
        aValue = severityOrder[a.severity];
        bValue = severityOrder[b.severity];
      }

      if (sortDirection === 'asc') {
        return aValue > bValue ? 1 : -1;
      } else {
        return aValue < bValue ? 1 : -1;
      }
    });
  }, [alerts, searchTerm, severityFilter, sortField, sortDirection]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('en-US', {
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return null;
    return sortDirection === 'asc' ? 
      <ChevronUp className="h-4 w-4" /> : 
      <ChevronDown className="h-4 w-4" />;
  };

  return (
    <div className="space-y-4">
      {/* Search and Filter Controls */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search alerts..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
        </div>
        
        <button
          onClick={() => setShowFilters(!showFilters)}
          className="flex items-center space-x-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors"
        >
          <Filter className="h-4 w-4" />
          <span>Filters</span>
        </button>
      </div>

      {/* Filter Panel */}
      {showFilters && (
        <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
          <div className="flex flex-wrap gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Severity
              </label>
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="all">All Severities</option>
                <option value="Low">Low</option>
                <option value="Medium">Medium</option>
                <option value="High">High</option>
                <option value="Critical">Critical</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Alerts Table */}
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th
                onClick={() => handleSort('timestamp')}
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
              >
                <div className="flex items-center space-x-1">
                  <span>Time</span>
                  <SortIcon field="timestamp" />
                </div>
              </th>
              <th
                onClick={() => handleSort('severity')}
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
              >
                <div className="flex items-center space-x-1">
                  <span>Severity</span>
                  <SortIcon field="severity" />
                </div>
              </th>
              <th
                onClick={() => handleSort('type')}
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
              >
                <div className="flex items-center space-x-1">
                  <span>Type</span>
                  <SortIcon field="type" />
                </div>
              </th>
              <th
                onClick={() => handleSort('source_ip')}
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
              >
                <div className="flex items-center space-x-1">
                  <span>Source IP</span>
                  <SortIcon field="source_ip" />
                </div>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                Description
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
            {filteredAndSortedAlerts.length > 0 ? (
              filteredAndSortedAlerts.map((alert) => (
                <tr key={alert.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                    {formatTimestamp(alert.timestamp)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${severityColors[alert.severity]}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                    {alert.type}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900 dark:text-white">
                    {alert.source_ip}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">
                    <div className="max-w-xs truncate" title={alert.description}>
                      {alert.description}
                    </div>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">
                  {alerts.length === 0 ? (
                    <div>
                      <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600 mx-auto mb-2"></div>
                      <p>Loading alerts...</p>
                    </div>
                  ) : (
                    <p>No alerts match your search criteria.</p>
                  )}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Results Summary */}
      {filteredAndSortedAlerts.length > 0 && (
        <div className="text-sm text-gray-500 dark:text-gray-400">
          Showing {filteredAndSortedAlerts.length} of {alerts.length} alerts
        </div>
      )}
    </div>
  );
}