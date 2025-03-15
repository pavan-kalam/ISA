import React, { useEffect, useState } from 'react';
import './Dashboard.css'; // You'll need to create this CSS file

function Dashboard() {
  const [threatLogs, setThreatLogs] = useState([]);
  const [riskScores] = useState([75, 85, 90]); // Example hardcoded risk scores
  const [averageRiskScore, setAverageRiskScore] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [realTimeAlerts, setRealTimeAlerts] = useState([]);
  const [threatCategories, setThreatCategories] = useState({});
  const [selectedThreat, setSelectedThreat] = useState('All');
  const [highRiskCount, setHighRiskCount] = useState(0);

  const [alertsByType, setAlertsByType] = useState({});

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      
      try {
        // Use Promise.all to fetch data in parallel
        const [threatLogsResponse, alertsResponse] = await Promise.all([
          fetch('http://localhost:5002/api/spiderfoot/threat-logs', {
            method: 'GET',
            headers: {
              'Content-Type': 'application/json',
            }
          }),
          fetch('http://localhost:5002/api/risk-scores', {
            method: 'GET',
            headers: {
              'Content-Type': 'application/json'
            }
          }),
          fetch('http://localhost:5002/api/real-time-alerts', {
            method: 'GET',
            headers: {
              'Content-Type': 'application/json'
            }
          })
        ]);

        // Check for response errors
        if (!threatLogsResponse.ok) {
          throw new Error(`Threat logs API failed with status: ${threatLogsResponse.status}`);
        }
        if (!alertsResponse.ok) {
          throw new Error(`Alerts API failed with status: ${alertsResponse.status}`);
        }

        // Parse the JSON responses
        const threatLogsData = await threatLogsResponse.json();
        const alertsData = await alertsResponse.json();
        console.log('Threat Logs Data:', threatLogsData); // Log the threat logs data for debugging
        console.log('Alerts Data:', alertsData); // Log the alerts data for debugging
        if (!Array.isArray(alertsData)) {
            setRealTimeAlerts([]); // Set to empty array if not valid
        } else {
            setRealTimeAlerts(alertsData); // Set alerts data if valid
        }

        // Update state with the data
        setThreatLogs(threatLogsData);
        setRealTimeAlerts(alertsData);
        
        // Analyze the data
        analyzeThreatLogs(threatLogsData);
        analyzeAlerts(alertsData);
      } catch (error) {
        console.error('Error fetching data:', error);
        setError(error.message);
        // Fallback to hardcoded data
        setThreatLogs([
          'Hardcoded Threat Log 1',
          'Hardcoded Threat Log 2',
          'Hardcoded Threat Log 3'
        ]);
        setRealTimeAlerts([
          'Hardcoded Alert 1',
          'Hardcoded Alert 2'
        ]);
        // Calculate average risk score
        const avg = riskScores.reduce((sum, score) => sum + score, 0) / riskScores.length;
        setAverageRiskScore(avg.toFixed(1));
        
        // Count high risk items
        const highRisks = riskScores.filter(score => score > 80).length;
        setHighRiskCount(highRisks);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [riskScores]);

  // Analyze threat logs to categorize by type
  const analyzeThreatLogs = (logs) => {
    const categories = {
      Malware: 0,
      Phishing: 0,
      IP: 0,
      Other: 0
    };
    
    logs.forEach(log => {
      if (log.includes('Malware')) {
        categories.Malware++;
      } else if (log.includes('Phishing')) {
        categories.Phishing++;
      } else if (log.includes('IP')) {
        categories.IP++;
      } else {
        categories.Other++;
      }
    });
    
    setThreatCategories(categories);
  };
  
  // Analyze alerts by type
  const analyzeAlerts = (alerts) => {
      if (typeof alerts !== 'object' || !Array.isArray(alerts)) {
          console.error('Expected alerts to be an array, received:', alerts);
          return;
      }

  const types = {
    'Suspicious login': 0,
    'Malware': 0,
    'Unusual traffic': 0,
    'Other': 0
  };
  
  alerts.forEach(alert => {
    if (alert.includes('Suspicious login')) {
      types['Suspicious login']++;
    } else if (alert.includes('malware')) {
      types['Malware']++;
    } else if (alert.includes('traffic')) {
      types['Unusual traffic']++;
    } else {
      types['Other']++;
    }
  });
  
  setAlertsByType(types);
};

  // Filter threat logs based on selected threat type
  const filteredThreatLogs = selectedThreat === 'All' 
    ? threatLogs 
    : threatLogs.filter(log => log.includes(selectedThreat));
    
  useEffect(() => {
    if (riskScores.length > 0) {
      const avg = riskScores.reduce((sum, score) => sum + score, 0) / riskScores.length;
      setAverageRiskScore(avg.toFixed(1));
      const highRisks = riskScores.filter(score => score > 80).length;
      setHighRiskCount(highRisks);
    }
  }, [riskScores, selectedThreat]);
    
  // Calculate average risk score and high risk count if riskScores are available
  useEffect(() => {
    if (riskScores.length > 0) {
      const avg = riskScores.reduce((sum, score) => sum + score, 0) / riskScores.length;
      setAverageRiskScore(avg.toFixed(1));
      const highRisks = riskScores.filter(score => score > 80).length;
      setHighRiskCount(highRisks);
    }
  }, [riskScores]);

  return (
    <div className="dashboard-container">
      <h1>Security Intelligence Dashboard</h1>
      
      {loading && <div className="loading-spinner">Loading dashboard data...</div>}
      
      {error && (
        <div className="error-message">
          <p>Error: {error}</p>
          <button onClick={() => window.location.reload()}>Retry</button>
        </div>
      )}
      
      {!loading && !error && (
        <>
          {/* Summary Cards */}
          <div className="summary-cards">
            <div className="summary-card">
              <h3>Total Threats</h3>
              <p className="summary-number">{threatLogs.length}</p>
              <div className="summary-breakdown">
                {Object.entries(threatCategories).map(([category, count]) => (
                  count > 0 && <div key={category}>{category}: {count}</div>
                ))}
              </div>
            </div>
            
            <div className="summary-card">
              <h3>Risk Assessment</h3>
              <p className="summary-number">N/A</p>
              <div className="risk-indicator" 
                   style={{
                     backgroundColor: 'gray'
                   }}>
              </div>
              <div>High risk items: {highRiskCount}</div>
            </div>
            
            <div className="summary-card">
              <h3>Active Alerts</h3>
              <p className="summary-number">{realTimeAlerts.length}</p>
              <div className="summary-breakdown">
                {Object.entries(alertsByType).map(([type, count]) => (
                  count > 0 && <div key={type}>{type}: {count}</div>
                ))}
              </div>
            </div>
          </div>
          
          {/* Detailed Sections */}
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
            </div>
            
            <div className="dashboard-section">
              <h2>Threat Logs Analysis</h2>
              <div className="analysis-summary">
                <p>
                  {threatLogs.length === 0 ? 'No threats detected.' : 
                   `${threatLogs.length} threats detected. ${
                     Object.entries(threatCategories)
                       .filter(([_, count]) => count > 0)
                       .map(([category, count]) => `${count} ${category.toLowerCase()}`)
                       .join(', ')
                   }.`
                  }
                </p>
              </div>
              <ul className="data-list">
                {filteredThreatLogs.length > 0 ? (
                  filteredThreatLogs.map((log, index) => (
                    <li key={index} className={
                      log.includes('Malware') ? 'threat-malware' :
                      log.includes('Phishing') ? 'threat-phishing' : 'threat-ip'
                    }>
                      {log}
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
                  Average risk score: <span className="highlight">{averageRiskScore}</span> 
                  {' '}({riskScores.length} measurements).
                  {highRiskCount > 0 && ` ${highRiskCount} high-risk items detected.`}
                </p>
              </div>
              <div className="risk-meter">
                {riskScores.map((score, index) => (
                  <div 
                    key={index}
                    className="risk-bar"
                    style={{
                      height: `${score}%`,
                      backgroundColor: score > 80 ? 'red' : score > 60 ? 'orange' : 'green'
                    }}
                    title={`Risk Score: ${score}`}
                  ></div>
                ))}
              </div>
              <ul className="data-list">
                {riskScores.length > 0 ? (
                  riskScores.map((score, index) => (
                    <li key={index} className={
                      score > 80 ? 'risk-high' :
                      score > 60 ? 'risk-medium' : 'risk-low'
                    }>
                      Risk Score: {score} - {
                        score > 80 ? 'Critical Attention Required' :
                        score > 60 ? 'Moderate Risk' : 'Low Risk'
                      }
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
                  {realTimeAlerts.length === 0 ? 'No active alerts.' : 
                   `${realTimeAlerts.length} active alerts. ${
                     Object.entries(alertsByType)
                       .filter(([_, count]) => count > 0)
                       .map(([type, count]) => `${count} ${type.toLowerCase()}`)
                       .join(', ')
                   }.`
                  }
                </p>
              </div>
              <ul className="data-list">
                {realTimeAlerts.length > 0 ? (
                  realTimeAlerts.map((alert, index) => (
                    <li key={index} className={
                      alert.includes('Suspicious login') ? 'alert-login' :
                      alert.includes('malware') ? 'alert-malware' : 
                      alert.includes('traffic') ? 'alert-traffic' : 'alert-other'
                    }>
                      {alert}
                      <span className="alert-time">{new Date().toLocaleTimeString()}</span>
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
  );
}

export default Dashboard;
