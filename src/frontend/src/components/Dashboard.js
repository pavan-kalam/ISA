// // src/frontend/src/components/Dashboard.js
// import React, { useEffect, useState } from 'react';

// function Dashboard() {
//     const [threatLogs, setThreatLogs] = useState([]);
//     const [riskScores, setRiskScores] = useState([]);
//     const [realTimeAlerts, setRealTimeAlerts] = useState([]);

//     useEffect(() => {
//         const fetchData = async () => {
//             try {
//                 const threatLogsResponse = await fetch('http://127.0.0.1:5000/api/threat-logs');
//                 const riskScoresResponse = await fetch('http://127.0.0.1:5000/api/risk-scores');
//                 const alertsResponse = await fetch('http://127.0.0.1:5000/api/real-time-alerts');

//                 const threatLogsData = await threatLogsResponse.json();
//                 const riskScoresData = await riskScoresResponse.json();
//                 const alertsData = await alertsResponse.json();

//                 setThreatLogs(threatLogsData);
//                 setRiskScores(riskScoresData);
//                 setRealTimeAlerts(alertsData);
//             } catch (error) {
//                 console.error('Error fetching data:', error);
//             }
//         };

//         fetchData();
//     }, []);

//     return (
//         <div>
//             <h1>Dashboard</h1>
//             <div className="dashboard-section">
//                 <h2>Threat Logs</h2>
//                 <ul>
//                     {threatLogs.length > 0 ? (
//                         threatLogs.map((log, index) => (
//                             <li key={index}>{log}</li>
//                         ))
//                     ) : (
//                         <li>No threat logs available.</li>
//                     )}
//                 </ul>
//             </div>
//             <div className="dashboard-section">
//                 <h2>Risk Scores</h2>
//                 <ul>
//                     {riskScores.length > 0 ? (
//                         riskScores.map((score, index) => (
//                             <li key={index}>Risk Score: {score}</li>
//                         ))
//                     ) : (
//                         <li>No risk scores available.</li>
//                     )}
//                 </ul>
//             </div>
//             <div className="dashboard-section">
//                 <h2>Real-Time Alerts</h2>
//                 <ul>
//                     {realTimeAlerts.length > 0 ? (
//                         realTimeAlerts.map((alert, index) => (
//                             <li key={index}>{alert}</li>
//                         ))
//                     ) : (
//                         <li>No real-time alerts available.</li>
//                     )}
//                 </ul>
//             </div>
//         </div>
//     );
// }

// export default Dashboard;




// // src/frontend/src/components/Dashboard.js
// import React, { useEffect, useState } from 'react';

// function Dashboard() {
//     const [threatLogs, setThreatLogs] = useState([]);
//     const [riskScores, setRiskScores] = useState([]);
//     const [realTimeAlerts, setRealTimeAlerts] = useState([]);
//     const [selectedThreat, setSelectedThreat] = useState('All');

//     useEffect(() => {
//         const fetchData = async () => {
//             try {
//                 const threatLogsResponse = await fetch('http://127.0.0.1:5000/api/threat-logs');
//                 const riskScoresResponse = await fetch('http://127.0.0.1:5000/api/risk-scores');
//                 const alertsResponse = await fetch('http://127.0.0.1:5000/api/real-time-alerts');

//                 const threatLogsData = await threatLogsResponse.json();
//                 const riskScoresData = await riskScoresResponse.json();
//                 const alertsData = await alertsResponse.json();

//                 setThreatLogs(threatLogsData);
//                 setRiskScores(riskScoresData);
//                 setRealTimeAlerts(alertsData);
//             } catch (error) {
//                 console.error('Error fetching data:', error);
//             }
//         };

//         fetchData();
//     }, []);

//     // Filter threat logs based on selected threat type
//     const filteredThreatLogs = selectedThreat === 'All' 
//         ? threatLogs 
//         : threatLogs.filter(log => log.includes(selectedThreat));

//     return (
//         <div>
//             <h1>Dashboard</h1>
//             <div>
//                 <label htmlFor="threat-select">Filter Threat Logs:</label>
//                 <select 
//                     id="threat-select" 
//                     value={selectedThreat} 
//                     onChange={(e) => setSelectedThreat(e.target.value)}
//                 >
//                     <option value="All">All</option>
//                     <option value="Malware">Malware</option>
//                     <option value="Phishing">Phishing</option>
//                     <option value="IP">IP</option>
//                 </select>
//             </div>
//             <div className="dashboard-section">
//                 <h2>Threat Logs</h2>
//                 <ul>
//                     {filteredThreatLogs.length > 0 ? (
//                         filteredThreatLogs.map((log, index) => (
//                             <li key={index}>{log}</li>
//                         ))
//                     ) : (
//                         <li>No threat logs available.</li>
//                     )}
//                 </ul>
//             </div>
//             <div className="dashboard-section">
//                 <h2>Risk Scores</h2>
//                 <ul>
//                     {riskScores.length > 0 ? (
//                         riskScores.map((score, index) => (
//                             <li key={index}>Risk Score: {score}</li>
//                         ))
//                     ) : (
//                         <li>No risk scores available.</li>
//                     )}
//                 </ul>
//             </div>
//             <div className="dashboard-section">
//                 <h2>Real-Time Alerts</h2>
//                 <ul>
//                     {realTimeAlerts.length > 0 ? (
//                         realTimeAlerts.map((alert, index) => (
//                             <li key={index}>{alert}</li>
//                         ))
//                     ) : (
//                         <li>No real-time alerts available.</li>
//                     )}
//                 </ul>
//             </div>
//         </div>
//     );
// }

// export default Dashboard;



import React, { useEffect, useState } from 'react';

function Dashboard() {
    const [threatLogs, setThreatLogs] = useState([]);
    const [riskScores, setRiskScores] = useState([]);
    const [realTimeAlerts, setRealTimeAlerts] = useState([]);
    const [selectedThreat, setSelectedThreat] = useState('All');

    useEffect(() => {
        const fetchData = async () => {
            try {
                const threatLogsResponse = await fetch('http://localhost:5000/api/threat-logs');
                const riskScoresResponse = await fetch('http://localhost:5000/api/risk-scores');
                const alertsResponse = await fetch('http://localhost:5000/api/real-time-alerts');

                if (!threatLogsResponse.ok || !riskScoresResponse.ok || !alertsResponse.ok) {
                    throw new Error('API request failed');
                }

                const threatLogsData = await threatLogsResponse.json();
                const riskScoresData = await riskScoresResponse.json();
                const alertsData = await alertsResponse.json();

                setThreatLogs(threatLogsData);
                setRiskScores(riskScoresData);
                setRealTimeAlerts(alertsData);
            } catch (error) {
                console.error('Error fetching data:', error);
            }
        };

        fetchData();
    }, []);

    // Filter threat logs based on selected threat type
    const filteredThreatLogs = selectedThreat === 'All' 
        ? threatLogs 
        : threatLogs.filter(log => log.includes(selectedThreat));

    return (
        <div>
            <h1>Dashboard</h1>
            <div>
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
            </div>
            <div className="dashboard-section">
                <h2>Threat Logs</h2>
                <ul>
                    {filteredThreatLogs.length > 0 ? (
                        filteredThreatLogs.map((log, index) => (
                            <li key={index}>{log}</li>
                        ))
                    ) : (
                        <li>No threat logs available.</li>
                    )}
                </ul>
            </div>
            <div className="dashboard-section">
                <h2>Risk Scores</h2>
                <ul>
                    {riskScores.length > 0 ? (
                        riskScores.map((score, index) => (
                            <li key={index}>Risk Score: {score}</li>
                        ))
                    ) : (
                        <li>No risk scores available.</li>
                    )}
                </ul>
            </div>
            <div className="dashboard-section">
                <h2>Real-Time Alerts</h2>
                <ul>
                    {realTimeAlerts.length > 0 ? (
                        realTimeAlerts.map((alert, index) => (
                            <li key={index}>{alert}</li>
                        ))
                    ) : (
                        <li>No real-time alerts available.</li>
                    )}
                </ul>
            </div>
        </div>
    );
}

export default Dashboard;
