import React, { useState, useEffect, useCallback, createContext, useContext } from 'react';
import { AlertCircle, Activity, Rss, Search, RefreshCw, Shield, TrendingUp, Clock, Database, 
         BarChart, PieChart, CheckCircle, XCircle, AlertTriangle, Download, Eye, Bell, 
         Moon, Sun, LogOut, User, Settings, FileText, Link, Calendar, Hash, Globe, 
         Lock, Unlock, BellOff, ChevronDown, X, Filter, ArrowUpDown, Copy, ExternalLink } from 'lucide-react';
import { LineChart, Line, BarChart as RechartsBarChart, Bar, PieChart as RechartsPieChart, 
         Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, 
         Area, AreaChart, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from 'recharts';

// Theme Context
const ThemeContext = createContext();

const ThemeProvider = ({ children }) => {
  const [isDarkMode, setIsDarkMode] = useState(false);
  
  const toggleDarkMode = () => setIsDarkMode(!isDarkMode);
  
  return (
    <ThemeContext.Provider value={{ isDarkMode, toggleDarkMode }}>
      {children}
    </ThemeContext.Provider>
  );
};

const useTheme = () => useContext(ThemeContext);

// Auth Context
const AuthContext = createContext();

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  
  const login = (username, password) => {
    // Mock authentication
    if (username === 'admin' && password === 'admin') {
      const mockUser = {
        id: 1,
        username: 'admin',
        email: 'admin@threatintel.com',
        role: 'administrator',
        permissions: ['read', 'write', 'delete', 'export']
      };
      setUser(mockUser);
      setIsAuthenticated(true);
      return { success: true };
    } else if (username === 'analyst' && password === 'analyst') {
      const mockUser = {
        id: 2,
        username: 'analyst',
        email: 'analyst@threatintel.com',
        role: 'analyst',
        permissions: ['read', 'export']
      };
      setUser(mockUser);
      setIsAuthenticated(true);
      return { success: true };
    }
    return { success: false, error: 'Invalid credentials' };
  };
  
  const logout = () => {
    setUser(null);
    setIsAuthenticated(false);
  };
  
  return (
    <AuthContext.Provider value={{ user, isAuthenticated, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => useContext(AuthContext);

// Notification System
const NotificationProvider = ({ children }) => {
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  
  const addNotification = (notification) => {
    const newNotification = {
      id: Date.now(),
      timestamp: new Date(),
      read: false,
      ...notification
    };
    setNotifications(prev => [newNotification, ...prev]);
    setUnreadCount(prev => prev + 1);
  };
  
  const markAsRead = (id) => {
    setNotifications(prev => 
      prev.map(n => n.id === id ? { ...n, read: true } : n)
    );
    setUnreadCount(prev => Math.max(0, prev - 1));
  };
  
  const clearAll = () => {
    setNotifications([]);
    setUnreadCount(0);
  };
  
  return (
    <NotificationContext.Provider value={{ notifications, unreadCount, addNotification, markAsRead, clearAll }}>
      {children}
    </NotificationContext.Provider>
  );
};

const NotificationContext = createContext();
const useNotifications = () => useContext(NotificationContext);

// Main Application Component
const ThreatIntelDashboard = () => {
  const { isDarkMode, toggleDarkMode } = useTheme();
  const { user, isAuthenticated, login, logout } = useAuth();
  const { notifications, unreadCount, addNotification, markAsRead, clearAll } = useNotifications();
  
  const [activeTab, setActiveTab] = useState('dashboard');
  const [indicators, setIndicators] = useState([]);
  const [feeds, setFeeds] = useState([]);
  const [statistics, setStatistics] = useState({
    totalIndicators: 0,
    recentActivity: 0,
    activeFeeds: 0,
    indicatorTypes: []
  });
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [selectedType, setSelectedType] = useState('all');
  const [timeRange, setTimeRange] = useState('24h');
  const [selectedIndicator, setSelectedIndicator] = useState(null);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [sortField, setSortField] = useState('lastSeen');
  const [sortDirection, setSortDirection] = useState('desc');
  const [apiConfig, setApiConfig] = useState({
    endpoint: 'https://api.threatintel.local',
    apiKey: '',
    refreshInterval: 300
  });

  // Mock data generation
  const generateMockData = useCallback(() => {
    // Generate mock indicators with more detailed data
    const mockIndicators = [
      {
        id: 1,
        indicator: 'malicious-domain.com',
        type: 'domain',
        threat: 'malware',
        severity: 'high',
        source: 'malware_domains',
        firstSeen: '2025-01-20T10:30:00',
        lastSeen: '2025-01-22T14:45:00',
        confidence: 85,
        tags: ['ransomware', 'c2'],
        description: 'Known malware distribution domain',
        ioc: { port: 443, protocol: 'https' },
        relatedIndicators: [2, 3],
        timeline: [
          { date: '2025-01-20T10:30:00', event: 'First detected' },
          { date: '2025-01-21T08:00:00', event: 'Activity spike observed' },
          { date: '2025-01-22T14:45:00', event: 'Last activity recorded' }
        ]
      },
      {
        id: 2,
        indicator: 'http://evil.example.com/malware.exe',
        type: 'url',
        threat: 'malware',
        severity: 'critical',
        source: 'abuse_ch_urlhaus',
        firstSeen: '2025-01-21T08:15:00',
        lastSeen: '2025-01-22T16:20:00',
        confidence: 95,
        tags: ['trojan', 'executable'],
        description: 'Direct malware download URL',
        ioc: { fileHash: '5d41402abc4b2a76b9719d911017c592', fileSize: '2.3MB' },
        relatedIndicators: [1, 3],
        timeline: [
          { date: '2025-01-21T08:15:00', event: 'URL discovered' },
          { date: '2025-01-21T12:00:00', event: 'Malware analysis completed' },
          { date: '2025-01-22T16:20:00', event: 'Still active' }
        ]
      },
      {
        id: 3,
        indicator: '192.168.1.100',
        type: 'ip',
        threat: 'botnet',
        severity: 'medium',
        source: 'internal_feed',
        firstSeen: '2025-01-19T12:00:00',
        lastSeen: '2025-01-22T15:30:00',
        confidence: 70,
        tags: ['botnet', 'suspicious'],
        description: 'Suspicious internal IP activity',
        ioc: { geoLocation: 'Internal Network', asn: 'AS12345' },
        relatedIndicators: [1, 2],
        timeline: [
          { date: '2025-01-19T12:00:00', event: 'Anomalous behavior detected' },
          { date: '2025-01-20T15:00:00', event: 'Communication with C2 server' },
          { date: '2025-01-22T15:30:00', event: 'Isolated from network' }
        ]
      }
    ];

    // Generate additional indicators
    for (let i = 4; i <= 50; i++) {
      const types = ['domain', 'url', 'ip', 'hash'];
      const threats = ['malware', 'phishing', 'botnet', 'c2', 'exploit'];
      const severities = ['low', 'medium', 'high', 'critical'];
      const sources = ['malware_domains', 'abuse_ch_urlhaus', 'virustotal', 'phishtank', 'internal_feed'];
      
      mockIndicators.push({
        id: i,
        indicator: `indicator-${i}.example.com`,
        type: types[Math.floor(Math.random() * types.length)],
        threat: threats[Math.floor(Math.random() * threats.length)],
        severity: severities[Math.floor(Math.random() * severities.length)],
        source: sources[Math.floor(Math.random() * sources.length)],
        firstSeen: new Date(Date.now() - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString(),
        lastSeen: new Date(Date.now() - Math.random() * 24 * 60 * 60 * 1000).toISOString(),
        confidence: Math.floor(Math.random() * 40) + 60,
        tags: [],
        description: 'Auto-generated test indicator',
        ioc: {},
        relatedIndicators: [],
        timeline: []
      });
    }

    setIndicators(mockIndicators);

    // Simulate new threat notification
    if (Math.random() > 0.7) {
      addNotification({
        type: 'threat',
        severity: 'high',
        title: 'New Critical Threat Detected',
        message: 'A new ransomware campaign has been identified targeting financial institutions.',
        indicator: mockIndicators[0]
      });
    }

    // Generate mock feeds
    const mockFeeds = [
      {
        name: 'malware_domains',
        url: 'https://malware-domains.com/files/domains.txt',
        type: 'domain',
        enabled: true,
        status: 'success',
        lastUpdated: '2025-01-22T16:00:00',
        indicatorCount: 1847,
        errorMessage: null
      },
      {
        name: 'abuse_ch_urlhaus',
        url: 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
        type: 'url',
        enabled: true,
        status: 'success',
        lastUpdated: '2025-01-22T15:30:00',
        indicatorCount: 2341,
        errorMessage: null
      },
      {
        name: 'phishtank',
        url: 'https://data.phishtank.com/data/online-valid.csv',
        type: 'url',
        enabled: true,
        status: 'error',
        lastUpdated: '2025-01-22T14:00:00',
        indicatorCount: 0,
        errorMessage: 'Connection timeout'
      }
    ];

    setFeeds(mockFeeds);

    // Calculate statistics
    const typeCount = mockIndicators.reduce((acc, indicator) => {
      acc[indicator.type] = (acc[indicator.type] || 0) + 1;
      return acc;
    }, {});

    const indicatorTypes = Object.entries(typeCount).map(([type, count]) => ({
      name: type,
      value: count
    }));

    const recentActivity = mockIndicators.filter(ind => {
      const hoursSince = (Date.now() - new Date(ind.lastSeen).getTime()) / (1000 * 60 * 60);
      return hoursSince <= 24;
    }).length;

    setStatistics({
      totalIndicators: mockIndicators.length,
      recentActivity,
      activeFeeds: mockFeeds.filter(f => f.status === 'success').length,
      indicatorTypes
    });
  }, [addNotification]);

  useEffect(() => {
    if (isAuthenticated) {
      generateMockData();
    }
  }, [isAuthenticated, generateMockData]);

  // Auto-refresh based on API config
  useEffect(() => {
    if (isAuthenticated && apiConfig.refreshInterval > 0) {
      const interval = setInterval(() => {
        refreshData();
      }, apiConfig.refreshInterval * 1000);
      
      return () => clearInterval(interval);
    }
  }, [isAuthenticated, apiConfig.refreshInterval]);

  // Login Component
  const LoginForm = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    
    const handleLogin = (e) => {
      e.preventDefault();
      const result = login(username, password);
      if (!result.success) {
        setError(result.error);
      }
    };
    
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <div className="max-w-md w-full space-y-8">
          <div>
            <div className="flex justify-center">
              <Shield className="w-12 h-12 text-blue-600" />
            </div>
            <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-white">
              Threat Intelligence Dashboard
            </h2>
            <p className="mt-2 text-center text-sm text-gray-600 dark:text-gray-400">
              Sign in to access threat intelligence data
            </p>
          </div>
          <div className="mt-8 space-y-6">
            <div className="rounded-md shadow-sm -space-y-px">
              <div>
                <label htmlFor="username" className="sr-only">Username</label>
                <input
                  id="username"
                  name="username"
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                  placeholder="Username"
                />
              </div>
              <div>
                <label htmlFor="password" className="sr-only">Password</label>
                <input
                  id="password"
                  name="password"
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                  placeholder="Password"
                />
              </div>
            </div>

            {error && (
              <div className="rounded-md bg-red-50 p-4">
                <p className="text-sm text-red-800">{error}</p>
              </div>
            )}

            <div>
              <button
                type="button"
                onClick={handleLogin}
                className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                <Lock className="w-4 h-4 mr-2" />
                Sign in
              </button>
            </div>
            
            <div className="text-sm text-center text-gray-600 dark:text-gray-400">
              Demo credentials: admin/admin or analyst/analyst
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Helper functions
  const hasPermission = (permission) => {
    return user?.permissions?.includes(permission) || false;
  };

  const refreshData = () => {
    setLoading(true);
    setTimeout(() => {
      generateMockData();
      setLoading(false);
      addNotification({
        type: 'info',
        title: 'Data Refreshed',
        message: 'All threat intelligence data has been updated.'
      });
    }, 1000);
  };

  const exportData = (format) => {
    if (!hasPermission('export')) {
      addNotification({
        type: 'error',
        title: 'Permission Denied',
        message: 'You do not have permission to export data.'
      });
      return;
    }

    const data = filteredIndicators;
    let content = '';
    let filename = `threat-indicators-${new Date().toISOString().split('T')[0]}`;
    let mimeType = '';

    switch (format) {
      case 'csv':
        const headers = ['Indicator', 'Type', 'Threat', 'Severity', 'Confidence', 'Source', 'First Seen', 'Last Seen', 'Tags', 'Description'];
        const csvRows = [
          headers.join(','),
          ...data.map(ind => [
            ind.indicator,
            ind.type,
            ind.threat,
            ind.severity,
            ind.confidence,
            ind.source,
            ind.firstSeen,
            ind.lastSeen,
            ind.tags.join(';'),
            `"${ind.description}"`
          ].join(','))
        ];
        content = csvRows.join('\n');
        filename += '.csv';
        mimeType = 'text/csv';
        break;

      case 'json':
        content = JSON.stringify(data, null, 2);
        filename += '.json';
        mimeType = 'application/json';
        break;

      case 'stix':
        // Mock STIX 2.1 format
        const stixBundle = {
          type: 'bundle',
          id: `bundle--${crypto.randomUUID ? crypto.randomUUID() : Date.now()}`,
          objects: data.map(ind => ({
            type: 'indicator',
            spec_version: '2.1',
            id: `indicator--${ind.id}`,
            created: ind.firstSeen,
            modified: ind.lastSeen,
            pattern: `[${ind.type}:value = '${ind.indicator}']`,
            pattern_type: 'stix',
            valid_from: ind.firstSeen,
            labels: [ind.threat],
            confidence: ind.confidence,
            description: ind.description
          }))
        };
        content = JSON.stringify(stixBundle, null, 2);
        filename += '.stix';
        mimeType = 'application/json';
        break;
    }

    // Create and download file
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    addNotification({
      type: 'success',
      title: 'Export Successful',
      message: `Exported ${data.length} indicators as ${format.toUpperCase()}`
    });
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      addNotification({
        type: 'success',
        title: 'Copied to Clipboard',
        message: 'Indicator copied successfully'
      });
    });
  };

  // Sorting function
  const sortIndicators = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  // Filter and sort indicators
  const filteredAndSortedIndicators = indicators
    .filter(indicator => {
      const matchesSearch = indicator.indicator.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           indicator.threat.toLowerCase().includes(searchQuery.toLowerCase()) ||
                           indicator.source.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesSeverity = selectedSeverity === 'all' || indicator.severity === selectedSeverity;
      const matchesType = selectedType === 'all' || indicator.type === selectedType;
      
      return matchesSearch && matchesSeverity && matchesType;
    })
    .sort((a, b) => {
      let aValue = a[sortField];
      let bValue = b[sortField];
      
      if (sortField === 'lastSeen' || sortField === 'firstSeen') {
        aValue = new Date(aValue).getTime();
        bValue = new Date(bValue).getTime();
      }
      
      if (sortDirection === 'asc') {
        return aValue > bValue ? 1 : -1;
      } else {
        return aValue < bValue ? 1 : -1;
      }
    });

  // Generate time series data
  const generateTimeSeriesData = () => {
    const hours = timeRange === '24h' ? 24 : timeRange === '7d' ? 168 : 720;
    const data = [];
    
    for (let i = hours; i >= 0; i -= hours / 10) {
      const time = new Date(Date.now() - i * 60 * 60 * 1000);
      data.push({
        time: timeRange === '24h' ? time.toLocaleTimeString() : time.toLocaleDateString(),
        indicators: Math.floor(Math.random() * 50) + 20,
        threats: Math.floor(Math.random() * 20) + 5,
        critical: Math.floor(Math.random() * 10) + 2
      });
    }
    
    return data;
  };

  // Threat radar data
  const generateRadarData = () => {
    return [
      { category: 'Malware', value: indicators.filter(i => i.threat === 'malware').length, fullMark: 20 },
      { category: 'Phishing', value: indicators.filter(i => i.threat === 'phishing').length, fullMark: 20 },
      { category: 'Botnet', value: indicators.filter(i => i.threat === 'botnet').length, fullMark: 20 },
      { category: 'C2', value: indicators.filter(i => i.threat === 'c2').length, fullMark: 20 },
      { category: 'Exploit', value: indicators.filter(i => i.threat === 'exploit').length, fullMark: 20 }
    ];
  };

  // Severity distribution
  const severityData = [
    { name: 'Critical', value: indicators.filter(i => i.severity === 'critical').length, color: '#dc2626' },
    { name: 'High', value: indicators.filter(i => i.severity === 'high').length, color: '#f97316' },
    { name: 'Medium', value: indicators.filter(i => i.severity === 'medium').length, color: '#eab308' },
    { name: 'Low', value: indicators.filter(i => i.severity === 'low').length, color: '#22c55e' }
  ];

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-600 dark:text-red-400';
      case 'high': return 'text-orange-500 dark:text-orange-400';
      case 'medium': return 'text-yellow-500 dark:text-yellow-400';
      case 'low': return 'text-green-500 dark:text-green-400';
      default: return 'text-gray-500 dark:text-gray-400';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'success': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'error': return <XCircle className="w-4 h-4 text-red-500" />;
      default: return <Clock className="w-4 h-4 text-gray-500" />;
    }
  };

  // Indicator Detail Modal
  const IndicatorDetailModal = () => {
    if (!selectedIndicator) return null;

    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
        <div className={`${isDarkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto`}>
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex justify-between items-start">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Indicator Details</h2>
              <button
                onClick={() => {
                  setSelectedIndicator(null);
                  setShowDetailModal(false);
                }}
                className="text-gray-400 hover:text-gray-500"
              >
                <X className="w-6 h-6" />
              </button>
            </div>
          </div>
          
          <div className="p-6 space-y-6">
            {/* Basic Information */}
            <div>
              <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Basic Information</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Indicator</label>
                  <div className="mt-1 flex items-center gap-2">
                    <code className="text-sm bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
                      {selectedIndicator.indicator}
                    </code>
                    <button
                      onClick={() => copyToClipboard(selectedIndicator.indicator)}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Type</label>
                  <div className="mt-1">
                    <span className="px-2 py-1 text-xs bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 rounded">
                      {selectedIndicator.type}
                    </span>
                  </div>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Threat</label>
                  <p className="mt-1 text-sm text-gray-900 dark:text-white">{selectedIndicator.threat}</p>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Severity</label>
                  <p className={`mt-1 text-sm font-medium ${getSeverityColor(selectedIndicator.severity)}`}>
                    {selectedIndicator.severity.toUpperCase()}
                  </p>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Confidence</label>
                  <div className="mt-1 flex items-center">
                    <span className="text-sm text-gray-900 dark:text-white">{selectedIndicator.confidence}%</span>
                    <div className="ml-2 w-24 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                      <div
                        className="bg-blue-600 h-2 rounded-full"
                        style={{ width: `${selectedIndicator.confidence}%` }}
                      />
                    </div>
                  </div>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Source</label>
                  <p className="mt-1 text-sm text-gray-900 dark:text-white">{selectedIndicator.source}</p>
                </div>
              </div>
            </div>
            
            {/* Description */}
            <div>
              <h3 className="text-lg font-semibold mb-2 text-gray-900 dark:text-white">Description</h3>
              <p className="text-sm text-gray-600 dark:text-gray-300">{selectedIndicator.description}</p>
            </div>
            
            {/* Tags */}
            {selectedIndicator.tags.length > 0 && (
              <div>
                <h3 className="text-lg font-semibold mb-2 text-gray-900 dark:text-white">Tags</h3>
                <div className="flex flex-wrap gap-2">
                  {selectedIndicator.tags.map((tag, index) => (
                    <span key={index} className="px-3 py-1 text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            )}
            
            {/* IOC Details */}
            {Object.keys(selectedIndicator.ioc).length > 0 && (
              <div>
                <h3 className="text-lg font-semibold mb-2 text-gray-900 dark:text-white">IOC Details</h3>
                <div className="bg-gray-50 dark:bg-gray-900 p-4 rounded-lg">
                  {Object.entries(selectedIndicator.ioc).map(([key, value]) => (
                    <div key={key} className="flex justify-between py-2 border-b border-gray-200 dark:border-gray-700 last:border-0">
                      <span className="text-sm font-medium text-gray-500 dark:text-gray-400">{key}:</span>
                      <span className="text-sm text-gray-900 dark:text-white">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {/* Timeline */}
            {selectedIndicator.timeline.length > 0 && (
              <div>
                <h3 className="text-lg font-semibold mb-2 text-gray-900 dark:text-white">Activity Timeline</h3>
                <div className="space-y-3">
                  {selectedIndicator.timeline.map((event, index) => (
                    <div key={index} className="flex items-start">
                      <div className="flex-shrink-0">
                        <div className="w-8 h-8 bg-blue-100 dark:bg-blue-900 rounded-full flex items-center justify-center">
                          <Calendar className="w-4 h-4 text-blue-600 dark:text-blue-300" />
                        </div>
                      </div>
                      <div className="ml-4">
                        <p className="text-sm font-medium text-gray-900 dark:text-white">{event.event}</p>
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          {new Date(event.date).toLocaleString()}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            
            {/* Related Indicators */}
            {selectedIndicator.relatedIndicators.length > 0 && (
              <div>
                <h3 className="text-lg font-semibold mb-2 text-gray-900 dark:text-white">Related Indicators</h3>
                <div className="space-y-2">
                  {selectedIndicator.relatedIndicators.map(id => {
                    const related = indicators.find(i => i.id === id);
                    if (!related) return null;
                    return (
                      <div key={id} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-900 rounded-lg">
                        <div className="flex items-center gap-3">
                          <Link className="w-4 h-4 text-gray-400" />
                          <code className="text-sm">{related.indicator}</code>
                          <span className="px-2 py-1 text-xs bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 rounded">
                            {related.type}
                          </span>
                        </div>
                        <button
                          onClick={() => {
                            setSelectedIndicator(related);
                          }}
                          className="text-blue-600 hover:text-blue-700 text-sm"
                        >
                          View Details
                        </button>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
            
            {/* Actions */}
            <div className="flex justify-end gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
              <button
                onClick={() => window.open(`https://www.virustotal.com/search?query=${selectedIndicator.indicator}`, '_blank')}
                className="flex items-center gap-2 px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
              >
                <ExternalLink className="w-4 h-4" />
                Check on VirusTotal
              </button>
              <button
                onClick={() => {
                  exportData('json');
                }}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
              >
                <Download className="w-4 h-4" />
                Export Details
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Notification Panel
  const NotificationPanel = () => {
    return (
      <div className={`absolute right-0 top-16 w-96 ${isDarkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow-xl border ${isDarkMode ? 'border-gray-700' : 'border-gray-200'} z-50`}>
        <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Notifications</h3>
          <button
            onClick={clearAll}
            className="text-sm text-blue-600 hover:text-blue-700"
          >
            Clear All
          </button>
        </div>
        
        <div className="max-h-96 overflow-y-auto">
          {notifications.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              <BellOff className="w-12 h-12 mx-auto mb-3 text-gray-300" />
              <p>No notifications</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-200 dark:divide-gray-700">
              {notifications.map(notification => (
                <div
                  key={notification.id}
                  className={`p-4 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer ${
                    !notification.read ? 'bg-blue-50 dark:bg-gray-700' : ''
                  }`}
                  onClick={() => markAsRead(notification.id)}
                >
                  <div className="flex items-start gap-3">
                    <div className={`w-2 h-2 rounded-full mt-2 ${
                      notification.type === 'threat' ? 'bg-red-500' :
                      notification.type === 'warning' ? 'bg-yellow-500' :
                      notification.type === 'success' ? 'bg-green-500' :
                      'bg-blue-500'
                    }`} />
                    <div className="flex-1">
                      <p className="text-sm font-medium text-gray-900 dark:text-white">
                        {notification.title}
                      </p>
                      <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
                        {notification.message}
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                        {new Date(notification.timestamp).toLocaleTimeString()}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  };

  // API Configuration Modal
  const ApiConfigModal = ({ show, onClose }) => {
    if (!show) return null;

    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
        <div className={`${isDarkMode ? 'bg-gray-800' : 'bg-white'} rounded-lg shadow-xl max-w-md w-full`}>
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">API Configuration</h2>
          </div>
          
          <div className="p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                API Endpoint
              </label>
              <input
                type="text"
                value={apiConfig.endpoint}
                onChange={(e) => setApiConfig({ ...apiConfig, endpoint: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                API Key
              </label>
              <input
                type="password"
                value={apiConfig.apiKey}
                onChange={(e) => setApiConfig({ ...apiConfig, apiKey: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Refresh Interval (seconds)
              </label>
              <input
                type="number"
                value={apiConfig.refreshInterval}
                onChange={(e) => setApiConfig({ ...apiConfig, refreshInterval: parseInt(e.target.value) })}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
              />
            </div>
            
            <div className="flex justify-end gap-3 pt-4">
              <button
                onClick={onClose}
                className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  addNotification({
                    type: 'success',
                    title: 'API Configuration Updated',
                    message: 'Your API settings have been saved.'
                  });
                  onClose();
                }}
                className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
              >
                Save
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderDashboard = () => (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold flex items-center gap-2 text-gray-900 dark:text-white">
          <Activity className="w-6 h-6" />
          Dashboard
        </h2>
        <div className="flex items-center gap-3">
          <button
            onClick={refreshData}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            disabled={loading}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <div className="relative">
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="relative p-2 bg-gray-200 dark:bg-gray-700 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
            >
              <Bell className="w-5 h-5 text-gray-700 dark:text-gray-300" />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full w-5 h-5 flex items-center justify-center">
                  {unreadCount}
                </span>
              )}
            </button>
            {showNotifications && <NotificationPanel />}
          </div>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 hover:shadow-xl transition-shadow">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 dark:text-gray-400 text-sm">Total Indicators</p>
              <p className="text-3xl font-bold mt-1 text-gray-900 dark:text-white">{statistics.totalIndicators}</p>
            </div>
            <AlertTriangle className="w-10 h-10 text-yellow-500" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 hover:shadow-xl transition-shadow">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 dark:text-gray-400 text-sm">Last 24h</p>
              <p className="text-3xl font-bold mt-1 text-gray-900 dark:text-white">{statistics.recentActivity}</p>
            </div>
            <Clock className="w-10 h-10 text-blue-500" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 hover:shadow-xl transition-shadow">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 dark:text-gray-400 text-sm">Active Feeds</p>
              <p className="text-3xl font-bold mt-1 text-gray-900 dark:text-white">{statistics.activeFeeds}</p>
            </div>
            <Rss className="w-10 h-10 text-green-500" />
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 hover:shadow-xl transition-shadow">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 dark:text-gray-400 text-sm">Critical Threats</p>
              <p className="text-3xl font-bold mt-1 text-gray-900 dark:text-white">
                {indicators.filter(i => i.severity === 'critical').length}
              </p>
            </div>
            <AlertCircle className="w-10 h-10 text-red-500" />
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Indicators by Type */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-gray-900 dark:text-white">
            <PieChart className="w-5 h-5" />
            Indicators by Type
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <RechartsPieChart>
              <Pie
                data={statistics.indicatorTypes}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {statistics.indicatorTypes.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={['#3b82f6', '#10b981', '#f59e0b', '#ef4444'][index % 4]} />
                ))}
              </Pie>
              <Tooltip />
            </RechartsPieChart>
          </ResponsiveContainer>
        </div>

        {/* Threat Radar */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-gray-900 dark:text-white">
            <Database className="w-5 h-5" />
            Threat Distribution
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <RadarChart data={generateRadarData()}>
              <PolarGrid stroke={isDarkMode ? '#374151' : '#e5e7eb'} />
              <PolarAngleAxis dataKey="category" tick={{ fill: isDarkMode ? '#9ca3af' : '#6b7280' }} />
              <PolarRadiusAxis angle={90} domain={[0, 20]} tick={{ fill: isDarkMode ? '#9ca3af' : '#6b7280' }} />
              <Radar name="Threats" dataKey="value" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.6} />
              <Tooltip />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Time Series Chart */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-semibold flex items-center gap-2 text-gray-900 dark:text-white">
            <TrendingUp className="w-5 h-5" />
            Threat Activity Timeline
          </h3>
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md text-sm dark:bg-gray-700 dark:text-white"
          >
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
        </div>
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={generateTimeSeriesData()}>
            <CartesianGrid strokeDasharray="3 3" stroke={isDarkMode ? '#374151' : '#e5e7eb'} />
            <XAxis dataKey="time" tick={{ fill: isDarkMode ? '#9ca3af' : '#6b7280' }} />
            <YAxis tick={{ fill: isDarkMode ? '#9ca3af' : '#6b7280' }} />
            <Tooltip contentStyle={{ backgroundColor: isDarkMode ? '#1f2937' : '#ffffff' }} />
            <Legend />
            <Area type="monotone" dataKey="indicators" stackId="1" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.6} />
            <Area type="monotone" dataKey="threats" stackId="1" stroke="#10b981" fill="#10b981" fillOpacity={0.6} />
            <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.6} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Recent Indicators */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold flex items-center gap-2 text-gray-900 dark:text-white">
            <Clock className="w-5 h-5" />
            Recent Indicators
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-900">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Indicator</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Threat</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Source</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Last Seen</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {indicators.slice(0, 10).map((indicator) => (
                <tr key={indicator.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <code className="text-sm bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">{indicator.indicator}</code>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                      {indicator.type}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-300">{indicator.threat}</td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`text-sm font-medium ${getSeverityColor(indicator.severity)}`}>
                      {indicator.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">{indicator.source}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {new Date(indicator.lastSeen).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <button
                      onClick={() => {
                        setSelectedIndicator(indicator);
                        setShowDetailModal(true);
                      }}
                      className="text-blue-600 hover:text-blue-700 text-sm"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  const renderIndicators = () => (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold flex items-center gap-2 text-gray-900 dark:text-white">
          <AlertCircle className="w-6 h-6" />
          Threat Indicators
        </h2>
        {hasPermission('export') && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => exportData('csv')}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              <Download className="w-4 h-4" />
              Export CSV
            </button>
            <button
              onClick={() => exportData('json')}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
            >
              <Download className="w-4 h-4" />
              Export JSON
            </button>
            <button
              onClick={() => exportData('stix')}
              className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors"
            >
              <Download className="w-4 h-4" />
              Export STIX
            </button>
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Search</label>
            <div className="relative">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search indicators..."
                className="w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
              />
              <Search className="absolute left-3 top-2.5 h-5 w-5 text-gray-400" />
            </div>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Type</label>
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
            >
              <option value="all">All Types</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="ip">IP</option>
              <option value="hash">Hash</option>
            </select>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Severity</label>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          
          <div className="flex items-end">
            <button
              onClick={() => {
                setSearchQuery('');
                setSelectedType('all');
                setSelectedSeverity('all');
              }}
              className="w-full px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
            >
              Clear Filters
            </button>
          </div>
        </div>
      </div>

      {/* Indicators Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-900">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  <button
                    onClick={() => sortIndicators('indicator')}
                    className="flex items-center gap-1 hover:text-gray-700 dark:hover:text-gray-200"
                  >
                    Indicator
                    <ArrowUpDown className="w-3 h-3" />
                  </button>
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Threat</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  <button
                    onClick={() => sortIndicators('severity')}
                    className="flex items-center gap-1 hover:text-gray-700 dark:hover:text-gray-200"
                  >
                    Severity
                    <ArrowUpDown className="w-3 h-3" />
                  </button>
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  <button
                    onClick={() => sortIndicators('confidence')}
                    className="flex items-center gap-1 hover:text-gray-700 dark:hover:text-gray-200"
                  >
                    Confidence
                    <ArrowUpDown className="w-3 h-3" />
                  </button>
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Source</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Tags</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  <button
                    onClick={() => sortIndicators('lastSeen')}
                    className="flex items-center gap-1 hover:text-gray-700 dark:hover:text-gray-200"
                  >
                    Last Seen
                    <ArrowUpDown className="w-3 h-3" />
                  </button>
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {filteredAndSortedIndicators.map((indicator) => (
                <tr key={indicator.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <code className="text-sm bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">{indicator.indicator}</code>
                      <button
                        onClick={() => copyToClipboard(indicator.indicator)}
                        className="text-gray-400 hover:text-gray-600"
                      >
                        <Copy className="w-3 h-3" />
                      </button>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                      {indicator.type}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-300">{indicator.threat}</td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`text-sm font-medium ${getSeverityColor(indicator.severity)}`}>
                      {indicator.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <div className="text-sm text-gray-900 dark:text-gray-300">{indicator.confidence}%</div>
                      <div className="ml-2 w-16 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                        <div
                          className="bg-blue-600 h-2 rounded-full"
                          style={{ width: `${indicator.confidence}%` }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">{indicator.source}</td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {indicator.tags.length > 0 && (
                      <div className="flex gap-1">
                        {indicator.tags.map((tag, index) => (
                          <span key={index} className="px-2 py-1 text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded">
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {new Date(indicator.lastSeen).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <button
                      onClick={() => {
                        setSelectedIndicator(indicator);
                        setShowDetailModal(true);
                      }}
                      className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  const renderFeeds = () => (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold flex items-center gap-2 text-gray-900 dark:text-white">
          <Rss className="w-6 h-6" />
          Threat Feeds
        </h2>
        <button
          onClick={refreshData}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Update All
        </button>
      </div>

      {/* Feeds Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {feeds.map((feed) => (
          <div key={feed.name} className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
            <div className="flex justify-between items-start mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{feed.name.replace(/_/g, ' ').toUpperCase()}</h3>
              <button className="p-2 bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-300 rounded-lg hover:bg-blue-200 dark:hover:bg-blue-800 transition-colors">
                <RefreshCw className="w-4 h-4" />
              </button>
            </div>
            
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500 dark:text-gray-400">Status</span>
                <div className="flex items-center gap-2">
                  {getStatusIcon(feed.status)}
                  <span className={`text-sm font-medium ${
                    feed.status === 'success' ? 'text-green-600 dark:text-green-400' : 
                    feed.status === 'error' ? 'text-red-600 dark:text-red-400' : 'text-gray-600 dark:text-gray-400'
                  }`}>
                    {feed.status.toUpperCase()}
                  </span>
                </div>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500 dark:text-gray-400">Type</span>
                <span className="px-2 py-1 text-xs bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 rounded">
                  {feed.type}
                </span>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500 dark:text-gray-400">Indicators</span>
                <span className="text-sm font-medium text-gray-900 dark:text-white">
                  {feed.indicatorCount.toLocaleString()}
                </span>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-500 dark:text-gray-400">Last Updated</span>
                <span className="text-sm text-gray-600 dark:text-gray-300">
                  {new Date(feed.lastUpdated).toLocaleString()}
                </span>
              </div>
              
              {feed.errorMessage && (
                <div className="mt-3 p-3 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 text-sm rounded-md">
                  {feed.errorMessage}
                </div>
              )}
              
              <div className="mt-4">
                <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">URL</div>
                <code className="text-xs bg-gray-100 dark:bg-gray-700 p-2 rounded block overflow-x-auto">
                  {feed.url}
                </code>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Feed Statistics */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">Feed Performance</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center">
            <div className="text-3xl font-bold text-green-600 dark:text-green-400">{feeds.filter(f => f.status === 'success').length}</div>
            <div className="text-sm text-gray-500 dark:text-gray-400 mt-1">Active Feeds</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-red-600 dark:text-red-400">{feeds.filter(f => f.status === 'error').length}</div>
            <div className="text-sm text-gray-500 dark:text-gray-400 mt-1">Failed Feeds</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-blue-600 dark:text-blue-400">
              {feeds.reduce((sum, feed) => sum + feed.indicatorCount, 0).toLocaleString()}
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400 mt-1">Total Indicators</div>
          </div>
        </div>
      </div>
    </div>
  );

  const renderSearch = () => (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold flex items-center gap-2 text-gray-900 dark:text-white">
          <Search className="w-6 h-6" />
          Search Indicators
        </h2>
      </div>

      {/* Search Form */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
        <div className="max-w-2xl mx-auto">
          <div className="relative">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search for domains, IPs, URLs, hashes..."
              className="w-full pl-12 pr-4 py-3 text-lg border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
              autoFocus
            />
            <Search className="absolute left-4 top-4 h-5 w-5 text-gray-400" />
          </div>
          
          <div className="mt-4 flex gap-2 flex-wrap">
            <button
              onClick={() => setSearchQuery('malicious-domain.com')}
              className="px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md text-sm hover:bg-gray-200 dark:hover:bg-gray-600"
            >
              Example: malicious-domain.com
            </button>
            <button
              onClick={() => setSearchQuery('192.168')}
              className="px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md text-sm hover:bg-gray-200 dark:hover:bg-gray-600"
            >
              Example: 192.168.*
            </button>
            <button
              onClick={() => setSearchQuery('malware')}
              className="px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md text-sm hover:bg-gray-200 dark:hover:bg-gray-600"
            >
              Example: malware
            </button>
          </div>
        </div>
      </div>

      {/* Search Results */}
      {searchQuery && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Search Results ({filteredAndSortedIndicators.length})
            </h3>
          </div>
          
          {filteredAndSortedIndicators.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 dark:bg-gray-900">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Indicator</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Type</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Threat</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Severity</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Source</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Description</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                  {filteredAndSortedIndicators.map((indicator) => (
                    <tr key={indicator.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <code className="text-sm bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">{indicator.indicator}</code>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                          {indicator.type}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-300">{indicator.threat}</td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`text-sm font-medium ${getSeverityColor(indicator.severity)}`}>
                          {indicator.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">{indicator.source}</td>
                      <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">{indicator.description}</td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <button
                          onClick={() => {
                            setSelectedIndicator(indicator);
                            setShowDetailModal(true);
                          }}
                          className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-12 text-center">
              <AlertCircle className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-500 dark:text-gray-400">No indicators found matching your search criteria.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );

  const renderSettings = () => (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold flex items-center gap-2 text-gray-900 dark:text-white">
        <Settings className="w-6 h-6" />
        Settings
      </h2>

      {/* API Configuration */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">API Configuration</h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              API Endpoint
            </label>
            <input
              type="text"
              value={apiConfig.endpoint}
              onChange={(e) => setApiConfig({ ...apiConfig, endpoint: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              API Key
            </label>
            <input
              type="password"
              value={apiConfig.apiKey}
              onChange={(e) => setApiConfig({ ...apiConfig, apiKey: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Auto-refresh Interval (seconds)
            </label>
            <input
              type="number"
              value={apiConfig.refreshInterval}
              onChange={(e) => setApiConfig({ ...apiConfig, refreshInterval: parseInt(e.target.value) })}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:text-white"
            />
          </div>
          
          <button
            onClick={() => {
              addNotification({
                type: 'success',
                title: 'Settings Saved',
                message: 'API configuration has been updated successfully.'
              });
            }}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
          >
            Save Configuration
          </button>
        </div>
      </div>

      {/* User Profile */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">User Profile</h3>
        <div className="space-y-3">
          <div>
            <span className="text-sm text-gray-500 dark:text-gray-400">Username:</span>
            <span className="ml-2 text-sm font-medium text-gray-900 dark:text-white">{user?.username}</span>
          </div>
          <div>
            <span className="text-sm text-gray-500 dark:text-gray-400">Email:</span>
            <span className="ml-2 text-sm font-medium text-gray-900 dark:text-white">{user?.email}</span>
          </div>
          <div>
            <span className="text-sm text-gray-500 dark:text-gray-400">Role:</span>
            <span className="ml-2 text-sm font-medium text-gray-900 dark:text-white">{user?.role}</span>
          </div>
          <div>
            <span className="text-sm text-gray-500 dark:text-gray-400">Permissions:</span>
            <div className="mt-1 flex gap-2">
              {user?.permissions.map((perm, index) => (
                <span key={index} className="px-2 py-1 text-xs bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200 rounded">
                  {perm}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  if (!isAuthenticated) {
    return <LoginForm />;
  }

  return (
    <div className={`min-h-screen ${isDarkMode ? 'dark bg-gray-900' : 'bg-gray-50'}`}>
      <div className="flex h-screen">
        {/* Sidebar */}
        <div className="w-64 bg-gray-900 dark:bg-black text-white">
          <div className="p-6">
            <h1 className="text-xl font-bold flex items-center gap-2">
              <Shield className="w-6 h-6" />
              Threat Intel
            </h1>
          </div>
          
          <nav className="px-4">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                activeTab === 'dashboard' ? 'bg-gray-800 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              }`}
            >
              <Activity className="w-5 h-5" />
              Dashboard
            </button>
            
            <button
              onClick={() => setActiveTab('indicators')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                activeTab === 'indicators' ? 'bg-gray-800 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              }`}
            >
              <AlertCircle className="w-5 h-5" />
              Indicators
            </button>
            
            <button
              onClick={() => setActiveTab('feeds')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                activeTab === 'feeds' ? 'bg-gray-800 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              }`}
            >
              <Rss className="w-5 h-5" />
              Feeds
            </button>
            
            <button
              onClick={() => setActiveTab('search')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                activeTab === 'search' ? 'bg-gray-800 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              }`}
            >
              <Search className="w-5 h-5" />
              Search
            </button>
            
            <button
              onClick={() => setActiveTab('settings')}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                activeTab === 'settings' ? 'bg-gray-800 text-white' : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              }`}
            >
              <Settings className="w-5 h-5" />
              Settings
            </button>
          </nav>
          
          <div className="absolute bottom-0 left-0 right-0 p-4">
            <div className="bg-gray-800 rounded-lg p-4 mb-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <User className="w-4 h-4 text-gray-400" />
                  <span className="text-sm text-gray-300">{user?.username}</span>
                </div>
                <button
                  onClick={toggleDarkMode}
                  className="text-gray-400 hover:text-white"
                >
                  {isDarkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
                </button>
              </div>
              <button
                onClick={logout}
                className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 text-sm"
              >
                <LogOut className="w-4 h-4" />
                Logout
              </button>
            </div>
            
            <div className="bg-gray-800 rounded-lg p-4">
              <div className="text-xs text-gray-400 mb-1">System Status</div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span className="text-sm text-gray-300">All Systems Operational</span>
              </div>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 overflow-y-auto">
          <div className="p-8">
            {activeTab === 'dashboard' && renderDashboard()}
            {activeTab === 'indicators' && renderIndicators()}
            {activeTab === 'feeds' && renderFeeds()}
            {activeTab === 'search' && renderSearch()}
            {activeTab === 'settings' && renderSettings()}
          </div>
        </div>
      </div>

      {/* Modals */}
      {showDetailModal && selectedIndicator && <IndicatorDetailModal />}
      <ApiConfigModal show={false} onClose={() => {}} />
    </div>
  );
};

// Main App Component with Providers
const App = () => {
  return (
    <ThemeProvider>
      <AuthProvider>
        <NotificationProvider>
          <ThreatIntelDashboard />
        </NotificationProvider>
      </AuthProvider>
    </ThemeProvider>
  );
};

export default App;
          