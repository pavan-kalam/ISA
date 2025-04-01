// // frontend/src/components/Dashboard.js
// import React, { useState, useEffect, useCallback, useRef } from 'react';
// import { Bar } from 'react-chartjs-2';
// import {
//   Chart as ChartJS,
//   CategoryScale,
//   LinearScale,
//   BarElement,
//   Title,
//   Tooltip,
//   Legend,
// } from 'chart.js';
// import './Dashboard.css';

// ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

// class ErrorBoundary extends React.Component {
//   state = { hasError: false, error: null };
//   static getDerivedStateFromError(error) {
//     return { hasError: true, error };
//   }
//   render() {
//     if (this.state.hasError) {
//       return (
//         <div className="error-message">
//           <h2>Something went wrong.</h2>
//           <p>{this.state.error?.message || 'Unknown error'}</p>
//           <button onClick={() => window.location.reload()}>Reload</button>
//         </div>
//       );
//     }
//     return this.props.children;
//   }
// }

// function Dashboard() {
//   const [threatLogs, setThreatLogs] = useState([]);
//   const [riskScores, setRiskScores] = useState([]);
//   const [averageRiskScore, setAverageRiskScore] = useState(0);
//   const [loading, setLoading] = useState(true);
//   const [error, setError] = useState(null);
//   const [realTimeAlerts, setRealTimeAlerts] = useState([]);
//   const [threatCategories, setThreatCategories] = useState({});
//   const [selectedThreat, setSelectedThreat] = useState('All');
//   const [highRiskCount, setHighRiskCount] = useState(0);
//   const [alertsByType, setAlertsByType] = useState({});
//   const [filter, setFilter] = useState({ severity: 'All', type: 'All', impact: 'All' });
//   const [assets, setAssets] = useState([]);
//   const [selectedAsset, setSelectedAsset] = useState('localhost:5002'); // Default query

//   const chartRef = useRef(null);

//   const fetchAssets = async () => {
//     try {
//       const response = await fetch('http://localhost:5002/api/assets');
//       if (!response.ok) throw new Error('Failed to fetch assets');
//       const assetsData = await response.json();
//       console.log('Assets:', assetsData);
//       setAssets(Array.isArray(assetsData) ? assetsData : []);
//     } catch (error) {
//       console.error('Error fetching assets:', error);
//       setError(error.message);
//     }
//   };

//   const fetchData = useCallback(async () => {
//     setLoading(true);
//     setError(null);

//     try {
//       const [threatLogsResponse, riskScoresResponse, alertsResponse] = await Promise.all([
//         fetch(`http://localhost:5002/api/spiderfoot/threat-logs?query=${encodeURIComponent(selectedAsset)}`, {
//           method: 'GET',
//           headers: { 'Content-Type': 'application/json' },
//         }),
//         fetch('http://localhost:5002/api/risk-scores', { method: 'GET', headers: { 'Content-Type': 'application/json' } }),
//         fetch('http://localhost:5002/api/real-time-alerts', { method: 'GET', headers: { 'Content-Type': 'application/json' } }),
//       ]);

//       const threatLogsData = threatLogsResponse.ok ? await threatLogsResponse.json() : [];
//       const riskScoresData = riskScoresResponse.ok ? await riskScoresResponse.json() : [];
//       const alertsData = alertsResponse.ok ? await alertsResponse.json() : [];

//       console.log('Threat Logs:', threatLogsData);
//       console.log('Risk Scores:', riskScoresData);
//       console.log('Real-Time Alerts:', alertsData);

//       setThreatLogs(Array.isArray(threatLogsData) ? threatLogsData : []);
//       setRiskScores(Array.isArray(riskScoresData) ? riskScoresData : [50, 75, 90]);
//       setRealTimeAlerts(Array.isArray(alertsData) ? alertsData : []);

//       analyzeThreatLogs(threatLogsData);
//       analyzeAlerts(alertsData);
//     } catch (error) {
//       console.error('Error fetching data:', error);
//       setError(error.message);
//       const fallbackThreatLogs = [{ log: 'Hardcoded Threat Log 1', response_plan: {} }, { log: 'Hardcoded Threat Log 2', response_plan: {} }];
//       const fallbackAlerts = [{ alert: 'Hardcoded Alert 1', response_plan: {} }, { alert: 'Hardcoded Alert 2', response_plan: {} }];
//       setThreatLogs(fallbackThreatLogs);
//       setRealTimeAlerts(fallbackAlerts);
//       setRiskScores([50, 75, 90]);
//       analyzeThreatLogs(fallbackThreatLogs);
//       analyzeAlerts(fallbackAlerts);
//     } finally {
//       setLoading(false);
//     }
//   }, [selectedAsset]);

//   const analyzeThreatLogs = (logs) => {
//     const categories = { Malware: 0, Phishing: 0, IP: 0, Other: 0 };
//     if (Array.isArray(logs)) {
//       logs.forEach((item) => {
//         const log = item?.log || '';
//         if (log.includes('Malware')) categories.Malware++;
//         else if (log.includes('Phishing')) categories.Phishing++;
//         else if (log.includes('IP')) categories.IP++;
//         else categories.Other++;
//       });
//     }
//     setThreatCategories(categories);
//   };

//   const analyzeAlerts = (alerts) => {
//     const types = { 'Suspicious login': 0, Malware: 0, 'Unusual traffic': 0, Other: 0 };
//     if (Array.isArray(alerts)) {
//       alerts.forEach((item) => {
//         const alert = item?.alert || '';
//         if (alert.includes('Suspicious login')) types['Suspicious login']++;
//         else if (alert.includes('malware')) types['Malware']++;
//         else if (alert.includes('traffic')) types['Unusual traffic']++;
//         else types['Other']++;
//       });
//     }
//     setAlertsByType(types);
//   };

//   const filterThreats = (threats) => {
//     if (!Array.isArray(threats)) return [];
//     return threats.filter((item) => {
//       const risk = parseInt(item?.log?.match(/Risk: (\d+)/)?.[1] || 0);
//       const type = item?.response_plan?.threat_type || 'Other';
//       const priority = item?.response_plan?.priority || 'Low';
//       return (
//         (filter.severity === 'All' || (filter.severity === 'High' && risk > 20) || (filter.severity === 'Low' && risk <= 20)) &&
//         (filter.type === 'All' || filter.type === type) &&
//         (filter.impact === 'All' || filter.impact === priority) &&
//         (selectedThreat === 'All' || (item?.log || '').includes(selectedThreat))
//       );
//     });
//   };

//   useEffect(() => {
//     fetchAssets();
//     fetchData();
//   }, [fetchData]);

//   useEffect(() => {
//     if (riskScores.length > 0) {
//       const avg = riskScores.reduce((sum, score) => sum + score, 0) / riskScores.length;
//       setAverageRiskScore(avg.toFixed(1));
//       const highRisks = riskScores.filter((score) => score > 20).length;
//       setHighRiskCount(highRisks);
//     }
//   }, [riskScores]);

//   const chartData = {
//     labels: riskScores.map((_, index) => `Threat ${index + 1}`),
//     datasets: [
//       {
//         label: 'Risk Scores',
//         data: riskScores,
//         backgroundColor: riskScores.map(score =>
//           score > 80 ? 'rgba(255, 99, 132, 0.6)' :
//           score > 60 ? 'rgba(255, 159, 64, 0.6)' :
//           'rgba(75, 192, 192, 0.6)'
//         ),
//         borderColor: riskScores.map(score =>
//           score > 80 ? 'rgba(255, 99, 132, 1)' :
//           score > 60 ? 'rgba(255, 159, 64, 1)' :
//           'rgba(75, 192, 192, 1)'
//         ),
//         borderWidth: 1,
//       },
//     ],
//   };

//   const chartOptions = {
//     responsive: true,
//     maintainAspectRatio: false,
//     plugins: {
//       legend: { position: 'top' },
//       title: { display: true, text: 'Risk Scores Overview' },
//     },
//     scales: {
//       y: { 
//         beginAtZero: true, 
//         max: 100, 
//         title: { display: true, text: 'Risk Score' } 
//       },
//       x: { title: { display: true, text: 'Threats' } },
//     },
//   };

//   return (
//     <ErrorBoundary>
//       <div className="dashboard-container">
//         <h1>Security Intelligence Dashboard</h1>
//         <div className="filter-container">
//           <label htmlFor="asset-select">Select Asset to Scan:</label>
//           <select
//             id="asset-select"
//             value={selectedAsset}
//             onChange={(e) => setSelectedAsset(e.target.value)}
//           >
//             <option value="localhost:5002">Default (localhost:5002)</option>
//             {assets.map((asset) => (
//               <option key={asset.id} value={asset.name}>
//                 {asset.name} ({asset.type})
//               </option>
//             ))}
//           </select>
//           <button onClick={fetchData}>Refresh Data</button>
//         </div>
//         {loading ? (
//           <div className="loading-spinner">Loading dashboard data...</div>
//         ) : error ? (
//           <div className="error-message">
//             <p>Error: {error}</p>
//             <button onClick={fetchData}>Retry</button>
//           </div>
//         ) : (
//           <>
//             <div className="summary-cards">
//               <div className="summary-card">
//                 <h3>Total Threats</h3>
//                 <p className="summary-number">{threatLogs.length}</p>
//                 <div className="summary-breakdown">
//                   {Object.entries(threatCategories)
//                     .filter(([_, count]) => count > 0)
//                     .map(([category, count]) => (
//                       <div key={category}>{category}: {count}</div>
//                     ))}
//                 </div>
//               </div>
//               <div className="summary-card">
//                 <h3>Risk Assessment</h3>
//                 <p className="summary-number">{averageRiskScore}</p>
//                 <div
//                   className="risk-indicator"
//                   style={{
//                     backgroundColor: highRiskCount > 5 || averageRiskScore > 60 ? 'red' : averageRiskScore > 30 ? 'orange' : 'green',
//                   }}
//                 />
//                 <div>High risk items: {highRiskCount}</div>
//               </div>
//               <div className="summary-card">
//                 <h3>Active Alerts</h3>
//                 <p className="summary-number">{realTimeAlerts.length}</p>
//                 <div className="summary-breakdown">
//                   {Object.entries(alertsByType)
//                     .filter(([_, count]) => count > 0)
//                     .map(([type, count]) => (
//                       <div key={type}>{type}: {count}</div>
//                     ))}
//                 </div>
//               </div>
//             </div>

//             <div className="dashboard-details">
//               <div className="filter-container">
//                 <label htmlFor="threat-select">Filter Threat Logs:</label>
//                 <select
//                   id="threat-select"
//                   value={selectedThreat}
//                   onChange={(e) => setSelectedThreat(e.target.value)}
//                 >
//                   <option value="All">All</option>
//                   <option value="Malware">Malware</option>
//                   <option value="Phishing">Phishing</option>
//                   <option value="IP">IP</option>
//                 </select>
//                 <label>Severity: </label>
//                 <select onChange={e => setFilter({ ...filter, severity: e.target.value })}>
//                   <option value="All">All</option>
//                   <option value="High">High (&gt;20)</option>
//                   <option value="Low">Low (&le;20)</option>
//                 </select>
//                 <label>Type: </label>
//                 <select onChange={e => setFilter({ ...filter, type: e.target.value })}>
//                   <option value="All">All</option>
//                   <option value="IP">IP</option>
//                   <option value="Other">Other</option>
//                 </select>
//                 <label>Impact: </label>
//                 <select onChange={e => setFilter({ ...filter, impact: e.target.value })}>
//                   <option value="All">All</option>
//                   <option value="High">High</option>
//                   <option value="Medium">Medium</option>
//                   <option value="Low">Low</option>
//                 </select>
//               </div>

//               <div className="chart-container">
//                 <h2>Risk Scores</h2>
//                 <div style={{ height: '400px', width: '100%' }}>
//                   <Bar data={chartData} options={chartOptions} ref={chartRef} />
//                 </div>
//               </div>

//               <div className="dashboard-section">
//                 <h2>Threat Logs Analysis</h2>
//                 <div className="analysis-summary">
//                   <p>
//                     {threatLogs.length === 0
//                       ? 'No threats detected.'
//                       : `${threatLogs.length} threats detected. ${Object.entries(threatCategories)
//                           .filter(([_, count]) => count > 0)
//                           .map(([category, count]) => `${count} ${category.toLowerCase()}`)
//                           .join(', ')}.`}
//                   </p>
//                 </div>
//                 <ul className="data-list">
//                   {filterThreats(threatLogs).length > 0 ? (
//                     filterThreats(threatLogs).map((item, index) => (
//                       <li
//                         key={index}
//                         className={
//                           (item?.log || '').includes('Malware')
//                             ? 'threat-malware'
//                             : (item?.log || '').includes('Phishing')
//                             ? 'threat-phishing'
//                             : 'threat-ip'
//                         }
//                       >
//                         <div className="threat-log">
//                           <strong>{item?.log || 'Unknown Threat'}</strong>
//                           {item?.cba && (
//                             <div className="cba-info">
//                               <p><strong>CBA:</strong> ${item.cba.cba} (Prior: ${item.cba.ale_prior}, Post: ${item.cba.ale_post}, ACS: ${item.cba.acs})</p>
//                             </div>
//                           )}
//                           {item?.response_plan && (
//                             <div className="response-plan">
//                               <h4>Response Plan (Priority: {item.response_plan.priority})</h4>
//                               <p><strong>Type:</strong> {item.response_plan.threat_type}</p>
//                               <p><strong>Description:</strong> {item.response_plan.description}</p>
//                               <h5>Mitigation Strategies:</h5>
//                               <ul>
//                                 {item?.response_plan?.mitigation_strategies?.map((strategy, idx) => (
//                                   <li key={idx}>{strategy}</li>
//                                 )) || <li>No mitigation strategies available</li>}
//                               </ul>
//                               <h5>Response Steps:</h5>
//                               <ol>
//                                 {item?.response_plan?.response_steps?.map((step, idx) => (
//                                   <li key={idx}>{step}</li>
//                                 )) || <li>No response steps available</li>}
//                               </ol>
//                             </div>
//                           )}
//                         </div>
//                       </li>
//                     ))
//                   ) : (
//                     <li>No threat logs available for the selected filter.</li>
//                   )}
//                 </ul>
//               </div>

//               <div className="dashboard-section">
//                 <h2>Risk Score Analysis</h2>
//                 <div className="analysis-summary">
//                   <p>
//                     Average risk score: <span className="highlight">{averageRiskScore}</span> ({riskScores.length}{' '}
//                     measurements). {highRiskCount > 0 && `${highRiskCount} high-risk items detected.`}
//                   </p>
//                 </div>
//                 <div className="risk-meter">
//                   {riskScores.map((score, index) => (
//                     <div
//                       key={index}
//                       className="risk-bar"
//                       style={{
//                         height: `${score}%`,
//                         backgroundColor: score > 80 ? 'red' : score > 60 ? 'orange' : 'green',
//                       }}
//                       title={`Risk Score: ${score}`}
//                     />
//                   ))}
//                 </div>
//                 <ul className="data-list">
//                   {riskScores.length > 0 ? (
//                     riskScores.map((score, index) => (
//                       <li
//                         key={index}
//                         className={score > 80 ? 'risk-high' : score > 60 ? 'risk-medium' : 'risk-low'}
//                       >
//                         Risk Score: {score} -{' '}
//                         {score > 80 ? 'Critical Attention Required' : score > 60 ? 'Moderate Risk' : 'Low Risk'}
//                       </li>
//                     ))
//                   ) : (
//                     <li>No risk scores available.</li>
//                   )}
//                 </ul>
//               </div>

//               <div className="dashboard-section">
//                 <h2>Real-Time Alerts Analysis</h2>
//                 <div className="analysis-summary">
//                   <p>
//                     {realTimeAlerts.length === 0
//                       ? 'No active alerts.'
//                       : `${realTimeAlerts.length} active alerts. ${Object.entries(alertsByType)
//                           .filter(([_, count]) => count > 0)
//                           .map(([type, count]) => `${count} ${type.toLowerCase()}`)
//                           .join(', ')}.`}
//                   </p>
//                 </div>
//                 <ul className="data-list">
//                   {realTimeAlerts.length > 0 ? (
//                     realTimeAlerts.map((item, index) => (
//                       <li
//                         key={index}
//                         className={
//                           (item?.alert || '').includes('Suspicious login')
//                             ? 'alert-login'
//                             : (item?.alert || '').includes('malware')
//                             ? 'alert-malware'
//                             : (item?.alert || '').includes('traffic')
//                             ? 'alert-traffic'
//                             : 'alert-other'
//                         }
//                       >
//                         <div className="alert-item">
//                           <strong>{item?.alert || 'Unknown Alert'}</strong>
//                           <span className="alert-time">{new Date().toLocaleTimeString()}</span>
//                           {item?.response_plan && (
//                             <div className="response-plan">
//                               <h4>Response Plan (Priority: {item.response_plan.priority})</h4>
//                               <p><strong>Type:</strong> {item.response_plan.threat_type}</p>
//                               <p><strong>Description:</strong> {item.response_plan.description}</p>
//                               <h5>Mitigation Strategies:</h5>
//                               <ul>
//                                 {item?.response_plan?.mitigation_strategies?.map((strategy, idx) => (
//                                   <li key={idx}>{strategy}</li>
//                                 )) || <li>No mitigation strategies available</li>}
//                               </ul>
//                               <h5>Response Steps:</h5>
//                               <ol>
//                                 {item?.response_plan?.response_steps?.map((step, idx) => (
//                                   <li key={idx}>{step}</li>
//                                 )) || <li>No response steps available</li>}
//                               </ol>
//                             </div>
//                           )}
//                         </div>
//                       </li>
//                     ))
//                   ) : (
//                     <li>No real-time alerts available.</li>
//                   )}
//                 </ul>
//               </div>
//             </div>
//           </>
//         )}
//       </div>
//     </ErrorBoundary>
//   );
// }

// export default Dashboard;


// // frontend/src/components/Dashboard.js
// import React, { useState, useEffect, useCallback, useRef } from 'react';
// import { Bar } from 'react-chartjs-2';
// import {
//   Chart as ChartJS,
//   CategoryScale,
//   LinearScale,
//   BarElement,
//   Title,
//   Tooltip,
//   Legend,
// } from 'chart.js';
// import './Dashboard.css';

// ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

// class ErrorBoundary extends React.Component {
//   state = { hasError: false, error: null };
//   static getDerivedStateFromError(error) {
//     return { hasError: true, error };
//   }
//   render() {
//     if (this.state.hasError) {
//       return (
//         <div className="error-message">
//           <h2>Something went wrong.</h2>
//           <p>{this.state.error?.message || 'Unknown error'}</p>
//           <button onClick={() => window.location.reload()}>Reload</button>
//         </div>
//       );
//     }
//     return this.props.children;
//   }
// }

// function Dashboard() {
//   const [threatLogs, setThreatLogs] = useState([]);
//   const [riskScores, setRiskScores] = useState([]);
//   const [averageRiskScore, setAverageRiskScore] = useState(0);
//   const [loadingThreatLogs, setLoadingThreatLogs] = useState(false);
//   const [loadingRiskScores, setLoadingRiskScores] = useState(false);
//   const [loadingRealTimeAlerts, setLoadingRealTimeAlerts] = useState(false);
//   const [error, setError] = useState(null);
//   const [realTimeAlerts, setRealTimeAlerts] = useState([]);
//   const [threatCategories, setThreatCategories] = useState({});
//   const [selectedThreat, setSelectedThreat] = useState('All');
//   const [highRiskCount, setHighRiskCount] = useState(0);
//   const [alertsByType, setAlertsByType] = useState({});
//   const [filter, setFilter] = useState({ severity: 'All', type: 'All', impact: 'All' });
//   const [assets, setAssets] = useState([]);
//   const [selectedAsset, setSelectedAsset] = useState('localhost:5002'); // Default query

//   const chartRef = useRef(null);

//   const fetchAssets = async () => {
//     try {
//       const response = await fetch('http://localhost:5002/api/assets');
//       if (!response.ok) throw new Error('Failed to fetch assets');
//       const assetsData = await response.json();
//       console.log('Assets:', assetsData);
//       setAssets(Array.isArray(assetsData) ? assetsData : []);
//     } catch (error) {
//       console.error('Error fetching assets:', error);
//       setError(error.message);
//     }
//   };

//   const fetchData = useCallback(async () => {
//     setError(null);

//     // Step 1: Fetch SpiderFoot threat logs first
//     setLoadingThreatLogs(true);
//     try {
//       const threatLogsResponse = await fetch(
//         `http://localhost:5002/api/spiderfoot/threat-logs?query=${encodeURIComponent(selectedAsset)}`,
//         {
//           method: 'GET',
//           headers: { 'Content-Type': 'application/json' },
//         }
//       );
//       const threatLogsData = threatLogsResponse.ok ? await threatLogsResponse.json() : [];
//       console.log('Threat Logs:', threatLogsData);
//       setThreatLogs(Array.isArray(threatLogsData) ? threatLogsData : []);
//       analyzeThreatLogs(threatLogsData);
//     } catch (error) {
//       console.error('Error fetching threat logs:', error);
//       setError(error.message);
//       const fallbackThreatLogs = [
//         { log: 'Hardcoded Threat Log 1', response_plan: {} },
//         { log: 'Hardcoded Threat Log 2', response_plan: {} },
//       ];
//       setThreatLogs(fallbackThreatLogs);
//       analyzeThreatLogs(fallbackThreatLogs);
//     } finally {
//       setLoadingThreatLogs(false);
//     }

//     // Step 2: Fetch risk scores after threat logs
//     setLoadingRiskScores(true);
//     try {
//       const riskScoresResponse = await fetch('http://localhost:5002/api/risk-scores', {
//         method: 'GET',
//         headers: { 'Content-Type': 'application/json' },
//       });
//       const riskScoresData = riskScoresResponse.ok ? await riskScoresResponse.json() : [];
//       console.log('Risk Scores:', riskScoresData);
//       setRiskScores(Array.isArray(riskScoresData) ? riskScoresData : [50, 75, 90]);
//     } catch (error) {
//       console.error('Error fetching risk scores:', error);
//       setError(error.message);
//       setRiskScores([50, 75, 90]);
//     } finally {
//       setLoadingRiskScores(false);
//     }

//     // Step 3: Fetch real-time alerts last
//     setLoadingRealTimeAlerts(true);
//     try {
//       const alertsResponse = await fetch(
//         `http://localhost:5002/api/real-time-alerts?query=${encodeURIComponent(selectedAsset)}`,
//         {
//           method: 'GET',
//           headers: { 'Content-Type': 'application/json' },
//         }
//       );
//       const alertsData = alertsResponse.ok ? await alertsResponse.json() : [];
//       console.log('Real-Time Alerts:', alertsData);
//       setRealTimeAlerts(Array.isArray(alertsData) ? alertsData : []);
//       analyzeAlerts(alertsData);
//     } catch (error) {
//       console.error('Error fetching real-time alerts:', error);
//       setError(error.message);
//       const fallbackAlerts = [
//         { alert: 'Hardcoded Alert 1', response_plan: {} },
//         { alert: 'Hardcoded Alert 2', response_plan: {} },
//       ];
//       setRealTimeAlerts(fallbackAlerts);
//       analyzeAlerts(fallbackAlerts);
//     } finally {
//       setLoadingRealTimeAlerts(false);
//     }
//   }, [selectedAsset]);

//   const analyzeThreatLogs = (logs) => {
//     const categories = { Malware: 0, Phishing: 0, IP: 0, Other: 0 };
//     if (Array.isArray(logs)) {
//       logs.forEach((item) => {
//         const log = item?.log || '';
//         if (log.includes('Malware')) categories.Malware++;
//         else if (log.includes('Phishing')) categories.Phishing++;
//         else if (log.includes('IP')) categories.IP++;
//         else categories.Other++;
//       });
//     }
//     setThreatCategories(categories);
//   };

//   const analyzeAlerts = (alerts) => {
//     const types = { 'Suspicious login': 0, Malware: 0, 'Unusual traffic': 0, Other: 0 };
//     if (Array.isArray(alerts)) {
//       alerts.forEach((item) => {
//         const alert = item?.alert || '';
//         if (alert.includes('Suspicious login')) types['Suspicious login']++;
//         else if (alert.includes('malware')) types['Malware']++;
//         else if (alert.includes('traffic')) types['Unusual traffic']++;
//         else types['Other']++;
//       });
//     }
//     setAlertsByType(types);
//   };

//   const filterThreats = (threats) => {
//     if (!Array.isArray(threats)) return [];
//     return threats.filter((item) => {
//       const risk = parseInt(item?.log?.match(/Risk: (\d+)/)?.[1] || 0);
//       const type = item?.response_plan?.threat_type || 'Other';
//       const priority = item?.response_plan?.priority || 'Low';
//       return (
//         (filter.severity === 'All' || (filter.severity === 'High' && risk > 20) || (filter.severity === 'Low' && risk <= 20)) &&
//         (filter.type === 'All' || filter.type === type) &&
//         (filter.impact === 'All' || filter.impact === priority) &&
//         (selectedThreat === 'All' || (item?.log || '').includes(selectedThreat))
//       );
//     });
//   };

//   useEffect(() => {
//     fetchAssets();
//     fetchData();
//   }, [fetchData]);

//   useEffect(() => {
//     if (riskScores.length > 0) {
//       const avg = riskScores.reduce((sum, score) => sum + score, 0) / riskScores.length;
//       setAverageRiskScore(avg.toFixed(1));
//       const highRisks = riskScores.filter((score) => score > 20).length;
//       setHighRiskCount(highRisks);
//     }
//   }, [riskScores]);

//   const chartData = {
//     labels: riskScores.map((_, index) => `Threat ${index + 1}`),
//     datasets: [
//       {
//         label: 'Risk Scores',
//         data: riskScores,
//         backgroundColor: riskScores.map(score =>
//           score > 80 ? 'rgba(255, 99, 132, 0.6)' :
//           score > 60 ? 'rgba(255, 159, 64, 0.6)' :
//           'rgba(75, 192, 192, 0.6)'
//         ),
//         borderColor: riskScores.map(score =>
//           score > 80 ? 'rgba(255, 99, 132, 1)' :
//           score > 60 ? 'rgba(255, 159, 64, 1)' :
//           'rgba(75, 192, 192, 1)'
//         ),
//         borderWidth: 1,
//       },
//     ],
//   };

//   const chartOptions = {
//     responsive: true,
//     maintainAspectRatio: false,
//     plugins: {
//       legend: { position: 'top' },
//       title: { display: true, text: 'Risk Scores Overview' },
//     },
//     scales: {
//       y: { 
//         beginAtZero: true, 
//         max: 100, 
//         title: { display: true, text: 'Risk Score' } 
//       },
//       x: { title: { display: true, text: 'Threats' } },
//     },
//   };

//   return (
//     <ErrorBoundary>
//       <div className="dashboard-container">
//         <h1>Security Intelligence Dashboard</h1>
//         <div className="filter-container">
//           <label htmlFor="asset-select">Select Asset to Scan:</label>
//           <select
//             id="asset-select"
//             value={selectedAsset}
//             onChange={(e) => setSelectedAsset(e.target.value)}
//           >
//             <option value="localhost:5002">Default (localhost:5002)</option>
//             {assets.map((asset) => (
//               <option key={asset.id} value={asset.name}>
//                 {asset.name} ({asset.type})
//               </option>
//             ))}
//           </select>
//           <button onClick={fetchData}>Refresh Data</button>
//         </div>
//         {error && (
//           <div className="error-message">
//             <p>Error: {error}</p>
//             <button onClick={fetchData}>Retry</button>
//           </div>
//         )}
//         <div className="summary-cards">
//           <div className="summary-card">
//             <h3>Total Threats</h3>
//             {loadingThreatLogs ? (
//               <p>Loading...</p>
//             ) : (
//               <>
//                 <p className="summary-number">{threatLogs.length}</p>
//                 <div className="summary-breakdown">
//                   {Object.entries(threatCategories)
//                     .filter(([_, count]) => count > 0)
//                     .map(([category, count]) => (
//                       <div key={category}>{category}: {count}</div>
//                     ))}
//                 </div>
//               </>
//             )}
//           </div>
//           <div className="summary-card">
//             <h3>Risk Assessment</h3>
//             {loadingRiskScores ? (
//               <p>Loading...</p>
//             ) : (
//               <>
//                 <p className="summary-number">{averageRiskScore}</p>
//                 <div
//                   className="risk-indicator"
//                   style={{
//                     backgroundColor: highRiskCount > 5 || averageRiskScore > 60 ? 'red' : averageRiskScore > 30 ? 'orange' : 'green',
//                   }}
//                 />
//                 <div>High risk items: {highRiskCount}</div>
//               </>
//             )}
//           </div>
//           <div className="summary-card">
//             <h3>Active Alerts</h3>
//             {loadingRealTimeAlerts ? (
//               <p>Loading...</p>
//             ) : (
//               <>
//                 <p className="summary-number">{realTimeAlerts.length}</p>
//                 <div className="summary-breakdown">
//                   {Object.entries(alertsByType)
//                     .filter(([_, count]) => count > 0)
//                     .map(([type, count]) => (
//                       <div key={type}>{type}: {count}</div>
//                     ))}
//                 </div>
//               </>
//             )}
//           </div>
//         </div>

//         <div className="dashboard-details">
//           <div className="filter-container">
//             <label htmlFor="threat-select">Filter Threat Logs:</label>
//             <select
//               id="threat-select"
//               value={selectedThreat}
//               onChange={(e) => setSelectedThreat(e.target.value)}
//             >
//               <option value="All">All</option>
//               <option value="Malware">Malware</option>
//               <option value="Phishing">Phishing</option>
//               <option value="IP">IP</option>
//             </select>
//             <label>Severity: </label>
//             <select onChange={e => setFilter({ ...filter, severity: e.target.value })}>
//               <option value="All">All</option>
//               <option value="High">High (&gt;20)</option>
//               <option value="Low">Low (&le;20)</option>
//             </select>
//             <label>Type: </label>
//             <select onChange={e => setFilter({ ...filter, type: e.target.value })}>
//               <option value="All">All</option>
//               <option value="IP">IP</option>
//               <option value="Other">Other</option>
//             </select>
//             <label>Impact: </label>
//             <select onChange={e => setFilter({ ...filter, impact: e.target.value })}>
//               <option value="All">All</option>
//               <option value="High">High</option>
//               <option value="Medium">Medium</option>
//               <option value="Low">Low</option>
//             </select>
//           </div>

//           <div className="chart-container">
//             <h2>Risk Scores</h2>
//             {loadingRiskScores ? (
//               <p>Loading risk scores...</p>
//             ) : (
//               <div style={{ height: '400px', width: '100%' }}>
//                 <Bar data={chartData} options={chartOptions} ref={chartRef} />
//               </div>
//             )}
//           </div>

//           <div className="dashboard-section">
//             <h2>Threat Logs Analysis</h2>
//             <div className="analysis-summary">
//               {loadingThreatLogs ? (
//                 <p>Loading threat logs...</p>
//               ) : (
//                 <p>
//                   {threatLogs.length === 0
//                     ? 'No threats detected.'
//                     : `${threatLogs.length} threats detected. ${Object.entries(threatCategories)
//                         .filter(([_, count]) => count > 0)
//                         .map(([category, count]) => `${count} ${category.toLowerCase()}`)
//                         .join(', ')}.`}
//                 </p>
//               )}
//             </div>
//             <ul className="data-list">
//               {loadingThreatLogs ? (
//                 <li>Loading threat logs...</li>
//               ) : filterThreats(threatLogs).length > 0 ? (
//                 filterThreats(threatLogs).map((item, index) => (
//                   <li
//                     key={index}
//                     className={
//                       (item?.log || '').includes('Malware')
//                         ? 'threat-malware'
//                         : (item?.log || '').includes('Phishing')
//                         ? 'threat-phishing'
//                         : 'threat-ip'
//                     }
//                   >
//                     <div className="threat-log">
//                       <strong>{item?.log || 'Unknown Threat'}</strong>
//                       {item?.cba && (
//                         <div className="cba-info">
//                           <p><strong>CBA:</strong> ${item.cba.cba} (Prior: ${item.cba.ale_prior}, Post: ${item.cba.ale_post}, ACS: ${item.cba.acs})</p>
//                         </div>
//                       )}
//                       {item?.response_plan && (
//                         <div className="response-plan">
//                           <h4>Response Plan (Priority: {item.response_plan.priority})</h4>
//                           <p><strong>Type:</strong> {item.response_plan.threat_type}</p>
//                           <p><strong>Description:</strong> {item.response_plan.description}</p>
//                           <h5>Mitigation Strategies:</h5>
//                           <ul>
//                             {item?.response_plan?.mitigation_strategies?.map((strategy, idx) => (
//                               <li key={idx}>{strategy}</li>
//                             )) || <li>No mitigation strategies available</li>}
//                           </ul>
//                           <h5>Response Steps:</h5>
//                           <ol>
//                             {item?.response_plan?.response_steps?.map((step, idx) => (
//                               <li key={idx}>{step}</li>
//                             )) || <li>No response steps available</li>}
//                           </ol>
//                         </div>
//                       )}
//                     </div>
//                   </li>
//                 ))
//               ) : (
//                 <li>No threat logs available for the selected filter.</li>
//               )}
//             </ul>
//           </div>

//           <div className="dashboard-section">
//             <h2>Risk Score Analysis</h2>
//             <div className="analysis-summary">
//               {loadingRiskScores ? (
//                 <p>Loading risk scores...</p>
//               ) : (
//                 <p>
//                   Average risk score: <span className="highlight">{averageRiskScore}</span> ({riskScores.length}{' '}
//                   measurements). {highRiskCount > 0 && `${highRiskCount} high-risk items detected.`}
//                 </p>
//               )}
//             </div>
//             <div className="risk-meter">
//               {loadingRiskScores ? (
//                 <p>Loading...</p>
//               ) : (
//                 riskScores.map((score, index) => (
//                   <div
//                     key={index}
//                     className="risk-bar"
//                     style={{
//                       height: `${score}%`,
//                       backgroundColor: score > 80 ? 'red' : score > 60 ? 'orange' : 'green',
//                     }}
//                     title={`Risk Score: ${score}`}
//                   />
//                 ))
//               )}
//             </div>
//             <ul className="data-list">
//               {loadingRiskScores ? (
//                 <li>Loading risk scores...</li>
//               ) : riskScores.length > 0 ? (
//                 riskScores.map((score, index) => (
//                   <li
//                     key={index}
//                     className={score > 80 ? 'risk-high' : score > 60 ? 'risk-medium' : 'risk-low'}
//                   >
//                     Risk Score: {score} -{' '}
//                     {score > 80 ? 'Critical Attention Required' : score > 60 ? 'Moderate Risk' : 'Low Risk'}
//                   </li>
//                 ))
//               ) : (
//                 <li>No risk scores available.</li>
//               )}
//             </ul>
//           </div>

//           <div className="dashboard-section">
//             <h2>Real-Time Alerts Analysis</h2>
//             <div className="analysis-summary">
//               {loadingRealTimeAlerts ? (
//                 <p>Loading real-time alerts...</p>
//               ) : (
//                 <p>
//                   {realTimeAlerts.length === 0
//                     ? 'No active alerts.'
//                     : `${realTimeAlerts.length} active alerts. ${Object.entries(alertsByType)
//                         .filter(([_, count]) => count > 0)
//                         .map(([type, count]) => `${count} ${type.toLowerCase()}`)
//                         .join(', ')}.`}
//                 </p>
//               )}
//             </div>
//             <ul className="data-list">
//               {loadingRealTimeAlerts ? (
//                 <li>Loading real-time alerts...</li>
//               ) : realTimeAlerts.length > 0 ? (
//                 realTimeAlerts.map((item, index) => (
//                   <li
//                     key={index}
//                     className={
//                       (item?.alert || '').includes('Suspicious login')
//                         ? 'alert-login'
//                         : (item?.alert || '').includes('malware')
//                         ? 'alert-malware'
//                         : (item?.alert || '').includes('traffic')
//                         ? 'alert-traffic'
//                         : 'alert-other'
//                     }
//                   >
//                     <div className="alert-item">
//                       <strong>{item?.alert || 'Unknown Alert'}</strong>
//                       <span className="alert-time">{new Date().toLocaleTimeString()}</span>
//                       {item?.response_plan && (
//                         <div className="response-plan">
//                           <h4>Response Plan (Priority: {item.response_plan.priority})</h4>
//                           <p><strong>Type:</strong> {item.response_plan.threat_type}</p>
//                           <p><strong>Description:</strong> {item.response_plan.description}</p>
//                           <h5>Mitigation Strategies:</h5>
//                           <ul>
//                             {item?.response_plan?.mitigation_strategies?.map((strategy, idx) => (
//                               <li key={idx}>{strategy}</li>
//                             )) || <li>No mitigation strategies available</li>}
//                           </ul>
//                           <h5>Response Steps:</h5>
//                           <ol>
//                             {item?.response_plan?.response_steps?.map((step, idx) => (
//                               <li key={idx}>{step}</li>
//                             )) || <li>No response steps available</li>}
//                           </ol>
//                         </div>
//                       )}
//                     </div>
//                   </li>
//                 ))
//               ) : (
//                 <li>No real-time alerts available.</li>
//               )}
//             </ul>
//           </div>
//         </div>
//       </div>
//     </ErrorBoundary>
//   );
// }

// export default Dashboard;





// frontend/src/components/Dashboard.js
import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import './Dashboard.css';

ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

class ErrorBoundary extends React.Component {
  state = { hasError: false, error: null };
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="error-message">
          <h2>Something went wrong.</h2>
          <p>{this.state.error?.message || 'Unknown error'}</p>
          <button onClick={() => window.location.reload()}>Reload</button>
        </div>
      );
    }
    return this.props.children;
  }
}

function Dashboard() {
  const [threatLogs, setThreatLogs] = useState([]);
  const [riskScores, setRiskScores] = useState([]);
  const [averageRiskScore, setAverageRiskScore] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [realTimeAlerts, setRealTimeAlerts] = useState([]);
  const [threatCategories, setThreatCategories] = useState({});
  const [selectedThreat, setSelectedThreat] = useState('All');
  const [highRiskCount, setHighRiskCount] = useState(0);
  const [alertsByType, setAlertsByType] = useState({});
  const [filter, setFilter] = useState({ severity: 'All', type: 'All', impact: 'All' });
  const [assets, setAssets] = useState([]);
  const [selectedAsset, setSelectedAsset] = useState('localhost:5002');

  const chartRef = useRef(null);

  const fetchAssets = async () => {
    try {
      const response = await fetch('http://localhost:5002/api/assets');
      if (!response.ok) throw new Error('Failed to fetch assets');
      const assetsData = await response.json();
      console.log('Assets:', assetsData);
      setAssets(Array.isArray(assetsData) ? assetsData : []);
    } catch (error) {
      console.error('Error fetching assets:', error);
      setError(error.message);
    }
  };

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const [threatLogsResponse, riskScoresResponse, alertsResponse] = await Promise.all([
        fetch(`http://localhost:5002/api/spiderfoot/threat-logs?query=${encodeURIComponent(selectedAsset)}`, {
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
        }),
        fetch(`http://localhost:5002/api/risk-scores?query=${encodeURIComponent(selectedAsset)}`, {  // Modified to pass selectedAsset
          method: 'GET',
          headers: { 'Content-Type': 'application/json' },
        }),
        fetch('http://localhost:5002/api/real-time-alerts', { method: 'GET', headers: { 'Content-Type': 'application/json' } }),
      ]);

      const threatLogsData = threatLogsResponse.ok ? await threatLogsResponse.json() : [];
      const riskScoresData = riskScoresResponse.ok ? await riskScoresResponse.json() : [];
      const alertsData = alertsResponse.ok ? await alertsResponse.json() : [];

      console.log('Threat Logs:', threatLogsData);
      console.log('Risk Scores:', riskScoresData);
      console.log('Real-Time Alerts:', alertsData);

      setThreatLogs(Array.isArray(threatLogsData) ? threatLogsData : []);
      setRiskScores(Array.isArray(riskScoresData) ? riskScoresData : [50, 75, 90]);
      setRealTimeAlerts(Array.isArray(alertsData) ? alertsData : []);

      analyzeThreatLogs(threatLogsData);
      analyzeAlerts(alertsData);
    } catch (error) {
      console.error('Error fetching data:', error);
      setError(error.message);
      const fallbackThreatLogs = [{ log: 'Hardcoded Threat Log 1', response_plan: {} }, { log: 'Hardcoded Threat Log 2', response_plan: {} }];
      const fallbackAlerts = [{ alert: 'Hardcoded Alert 1', response_plan: {} }, { alert: 'Hardcoded Alert 2', response_plan: {} }];
      setThreatLogs(fallbackThreatLogs);
      setRealTimeAlerts(fallbackAlerts);
      setRiskScores([50, 75, 90]);
      analyzeThreatLogs(fallbackThreatLogs);
      analyzeAlerts(fallbackAlerts);
    } finally {
      setLoading(false);
    }
  }, [selectedAsset]);

  const analyzeThreatLogs = (logs) => {
    const categories = { Malware: 0, Phishing: 0, IP: 0, Other: 0 };
    if (Array.isArray(logs)) {
      logs.forEach((item) => {
        const log = item?.log || '';
        if (log.includes('Malware')) categories.Malware++;
        else if (log.includes('Phishing')) categories.Phishing++;
        else if (log.includes('IP')) categories.IP++;
        else categories.Other++;
      });
    }
    setThreatCategories(categories);
  };

  const analyzeAlerts = (alerts) => {
    const types = { 'Suspicious login': 0, Malware: 0, 'Unusual traffic': 0, Other: 0 };
    if (Array.isArray(alerts)) {
      alerts.forEach((item) => {
        const alert = item?.alert || '';
        if (alert.includes('Suspicious login')) types['Suspicious login']++;
        else if (alert.includes('malware')) types['Malware']++;
        else if (alert.includes('traffic')) types['Unusual traffic']++;
        else types['Other']++;
      });
    }
    setAlertsByType(types);
  };

  const filterThreats = (threats) => {
    if (!Array.isArray(threats)) return [];
    return threats.filter((item) => {
      const risk = parseInt(item?.log?.match(/Risk: (\d+)/)?.[1] || 0);
      const type = item?.response_plan?.threat_type || 'Other';
      const priority = item?.response_plan?.priority || 'Low';
      return (
        (filter.severity === 'All' || (filter.severity === 'High' && risk > 20) || (filter.severity === 'Low' && risk <= 20)) &&
        (filter.type === 'All' || filter.type === type) &&
        (filter.impact === 'All' || filter.impact === priority) &&
        (selectedThreat === 'All' || (item?.log || '').includes(selectedThreat))
      );
    });
  };

  useEffect(() => {
    fetchAssets();
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    if (riskScores.length > 0) {
      const avg = riskScores.reduce((sum, score) => sum + score, 0) / riskScores.length;
      setAverageRiskScore(avg.toFixed(1));
      const highRisks = riskScores.filter((score) => score > 20).length;
      setHighRiskCount(highRisks);
    }
  }, [riskScores]);

  const chartData = {
    labels: riskScores.map((_, index) => `Threat ${index + 1}`),
    datasets: [
      {
        label: 'Risk Scores',
        data: riskScores,
        backgroundColor: riskScores.map(score =>
          score > 80 ? 'rgba(255, 99, 132, 0.6)' :
          score > 60 ? 'rgba(255, 159, 64, 0.6)' :
          'rgba(75, 192, 192, 0.6)'
        ),
        borderColor: riskScores.map(score =>
          score > 80 ? 'rgba(255, 99, 132, 1)' :
          score > 60 ? 'rgba(255, 159, 64, 1)' :
          'rgba(75, 192, 192, 1)'
        ),
        borderWidth: 1,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: 'top' },
      title: { display: true, text: 'Risk Scores Overview' },
    },
    scales: {
      y: {
        beginAtZero: true,
        max: 100,
        title: { display: true, text: 'Risk Score' }
      },
      x: { title: { display: true, text: 'Threats' } },
    },
  };

  return (
    <ErrorBoundary>
      <div className="dashboard-container">
        <h1>Security Intelligence Dashboard</h1>
        <div className="filter-container">
          <label htmlFor="asset-select">Select Asset to Scan:</label>
          <select
            id="asset-select"
            value={selectedAsset}
            onChange={(e) => setSelectedAsset(e.target.value)}
          >
            <option value="localhost:5002">Default (localhost:5002)</option>
            {assets.map((asset) => (
              <option key={asset.id} value={asset.name}>
                {asset.name} ({asset.type})
              </option>
            ))}
          </select>
          <button onClick={fetchData}>Refresh Data</button>
        </div>
        {loading ? (
          <div className="loading-spinner">Loading dashboard data...</div>
        ) : error ? (
          <div className="error-message">
            <p>Error: {error}</p>
            <button onClick={fetchData}>Retry</button>
          </div>
        ) : (
          <>
            <div className="summary-cards">
              <div className="summary-card">
                <h3>Total Threats</h3>
                <p className="summary-number">{threatLogs.length}</p>
                <div className="summary-breakdown">
                  {Object.entries(threatCategories)
                    .filter(([_, count]) => count > 0)
                    .map(([category, count]) => (
                      <div key={category}>{category}: {count}</div>
                    ))}
                </div>
              </div>
              <div className="summary-card">
                <h3>Risk Assessment</h3>
                <p className="summary-number">{averageRiskScore}</p>
                <div
                  className="risk-indicator"
                  style={{
                    backgroundColor: highRiskCount > 5 || averageRiskScore > 60 ? 'red' : averageRiskScore > 30 ? 'orange' : 'green',
                  }}
                />
                <div>High risk items: {highRiskCount}</div>
              </div>
              <div className="summary-card">
                <h3>Active Alerts</h3>
                <p className="summary-number">{realTimeAlerts.length}</p>
                <div className="summary-breakdown">
                  {Object.entries(alertsByType)
                    .filter(([_, count]) => count > 0)
                    .map(([type, count]) => (
                      <div key={type}>{type}: {count}</div>
                    ))}
                </div>
              </div>
            </div>

            <div className="dashboard-details">
              <div className="filter-container">
                <label htmlFor="threat-select">Filter Threat Logs:</label>
                <select
                  id="threat-select"
                  value={selectedThreat}
                  onChange={(e) => setSelectedThreat(e.target.value)}
                >
                  <option value="All">All</option>
                  <option value="Malware">Malware</option>
                  <option value="Phishing">Phishing</option>
                  <option value="IP">IP</option>
                </select>
                <label>Severity: </label>
                <select onChange={e => setFilter({ ...filter, severity: e.target.value })}>
                  <option value="All">All</option>
                  <option value="High">High (&gt;20)</option>
                  <option value="Low">Low (&le;20)</option>
                </select>
                <label>Type: </label>
                <select onChange={e => setFilter({ ...filter, type: e.target.value })}>
                  <option value="All">All</option>
                  <option value="IP">IP</option>
                  <option value="Other">Other</option>
                </select>
                <label>Impact: </label>
                <select onChange={e => setFilter({ ...filter, impact: e.target.value })}>
                  <option value="All">All</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              <div className="chart-container">
                <h2>Risk Scores</h2>
                <div style={{ height: '400px', width: '100%' }}>
                  <Bar data={chartData} options={chartOptions} ref={chartRef} />
                </div>
              </div>

              <div className="dashboard-section">
                <h2>Threat Logs Analysis</h2>
                <div className="analysis-summary">
                  <p>
                    {threatLogs.length === 0
                      ? 'No threats detected.'
                      : `${threatLogs.length} threats detected. ${Object.entries(threatCategories)
                          .filter(([_, count]) => count > 0)
                          .map(([category, count]) => `${count} ${category.toLowerCase()}`)
                          .join(', ')}.`}
                  </p>
                </div>
                <ul className="data-list">
                  {filterThreats(threatLogs).length > 0 ? (
                    filterThreats(threatLogs).map((item, index) => (
                      <li
                        key={index}
                        className={
                          (item?.log || '').includes('Malware')
                            ? 'threat-malware'
                            : (item?.log || '').includes('Phishing')
                            ? 'threat-phishing'
                            : 'threat-ip'
                        }
                      >
                        <div className="threat-log">
                          <strong>{item?.log || 'Unknown Threat'}</strong>
                          {item?.cba && (
                            <div className="cba-info">
                              <p><strong>CBA:</strong> ${item.cba.cba} (Prior: ${item.cba.ale_prior}, Post: ${item.cba.ale_post}, ACS: ${item.cba.acs})</p>
                            </div>
                          )}
                          {item?.response_plan && (
                            <div className="response-plan">
                              <h4>Response Plan (Priority: {item.response_plan.priority})</h4>
                              <p><strong>Type:</strong> {item.response_plan.threat_type}</p>
                              <p><strong>Description:</strong> {item.response_plan.description}</p>
                              <h5>Mitigation Strategies:</h5>
                              <ul>
                                {item?.response_plan?.mitigation_strategies?.map((strategy, idx) => (
                                  <li key={idx}>{strategy}</li>
                                )) || <li>No mitigation strategies available</li>}
                              </ul>
                              <h5>Response Steps:</h5>
                              <ol>
                                {item?.response_plan?.response_steps?.map((step, idx) => (
                                  <li key={idx}>{step}</li>
                                )) || <li>No response steps available</li>}
                              </ol>
                            </div>
                          )}
                        </div>
                      </li>
                    ))
                  ) : (
                    <li>No threat logs available for the selected filter.</li>
                  )}
                </ul>
              </div>

              <div className="dashboard-section">
                <h2>Risk Score Analysis</h2>
                <div className="analysis-summary">
                  <p>
                    Average risk score: <span className="highlight">{averageRiskScore}</span> ({riskScores.length}{' '}
                    measurements). {highRiskCount > 0 && `${highRiskCount} high-risk items detected.`}
                  </p>
                </div>
                <div className="risk-meter">
                  {riskScores.map((score, index) => (
                    <div
                      key={index}
                      className="risk-bar"
                      style={{
                        height: `${score}%`,
                        backgroundColor: score > 80 ? 'red' : score > 60 ? 'orange' : 'green',
                      }}
                      title={`Risk Score: ${score}`}
                    />
                  ))}
                </div>
                <ul className="data-list">
                  {riskScores.length > 0 ? (
                    riskScores.map((score, index) => (
                      <li
                        key={index}
                        className={score > 80 ? 'risk-high' : score > 60 ? 'risk-medium' : 'risk-low'}
                      >
                        Risk Score: {score} -{' '}
                        {score > 80 ? 'Critical Attention Required' : score > 60 ? 'Moderate Risk' : 'Low Risk'}
                      </li>
                    ))
                  ) : (
                    <li>No risk scores available.</li>
                  )}
                </ul>
              </div>

              <div className="dashboard-section">
                <h2>Real-Time Alerts Analysis</h2>
                <div className="analysis-summary">
                  <p>
                    {realTimeAlerts.length === 0
                      ? 'No active alerts.'
                      : `${realTimeAlerts.length} active alerts. ${Object.entries(alertsByType)
                          .filter(([_, count]) => count > 0)
                          .map(([type, count]) => `${count} ${type.toLowerCase()}`)
                          .join(', ')}.`}
                  </p>
                </div>
                <ul className="data-list">
                  {realTimeAlerts.length > 0 ? (
                    realTimeAlerts.map((item, index) => (
                      <li
                        key={index}
                        className={
                          (item?.alert || '').includes('Suspicious login')
                            ? 'alert-login'
                            : (item?.alert || '').includes('malware')
                            ? 'alert-malware'
                            : (item?.alert || '').includes('traffic')
                            ? 'alert-traffic'
                            : 'alert-other'
                        }
                      >
                        <div className="alert-item">
                          <strong>{item?.alert || 'Unknown Alert'}</strong>
                          <span className="alert-time">{new Date().toLocaleTimeString()}</span>
                          {item?.response_plan && (
                            <div className="response-plan">
                              <h4>Response Plan (Priority: {item.response_plan.priority})</h4>
                              <p><strong>Type:</strong> {item.response_plan.threat_type}</p>
                              <p><strong>Description:</strong> {item.response_plan.description}</p>
                              <h5>Mitigation Strategies:</h5>
                              <ul>
                                {item?.response_plan?.mitigation_strategies?.map((strategy, idx) => (
                                  <li key={idx}>{strategy}</li>
                                )) || <li>No mitigation strategies available</li>}
                              </ul>
                              <h5>Response Steps:</h5>
                              <ol>
                                {item?.response_plan?.response_steps?.map((step, idx) => (
                                  <li key={idx}>{step}</li>
                                )) || <li>No response steps available</li>}
                              </ol>
                            </div>
                          )}
                          {item?.llm_insights && (  // Added to display LLM insights
                            <div className="llm-insights">
                              <h4>LLM Analysis</h4>
                              <p><strong>Severity:</strong> {item.llm_insights.severity} (Confidence: {item.llm_insights.confidence})</p>
                              <p><strong>Suggested Action:</strong> {item.llm_insights.suggested_action}</p>
                            </div>
                          )}
                        </div>
                      </li>
                    ))
                  ) : (
                    <li>No real-time alerts available.</li>
                  )}
                </ul>
              </div>
            </div>
          </>
        )}
      </div>
    </ErrorBoundary>
  );
}

export default Dashboard;