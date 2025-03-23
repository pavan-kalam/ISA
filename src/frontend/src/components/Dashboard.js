import React, { useEffect, useState } from 'react';
import './Dashboard.css';

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

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);

      try {
        const [threatLogsResponse, riskScoresResponse, alertsResponse] = await Promise.all([
          fetch('http://localhost:5002/api/spiderfoot/threat-logs', {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
          }),
          fetch('http://localhost:5002/api/risk-scores', {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
          }),
          fetch('http://localhost:5002/api/real-time-alerts', {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
          }),
        ]);

        if (!threatLogsResponse.ok) throw new Error(`Threat logs API failed: ${threatLogsResponse.status}`);
        if (!riskScoresResponse.ok) throw new Error(`Risk scores API failed: ${riskScoresResponse.status}`);
        if (!alertsResponse.ok) throw new Error(`Alerts API failed: ${alertsResponse.status}`);

        const threatLogsData = await threatLogsResponse.json();
        const riskScoresData = await riskScoresResponse.json();
        const alertsData = await alertsResponse.json();

        setThreatLogs(Array.isArray(threatLogsData) ? threatLogsData : []);
        setRiskScores(Array.isArray(riskScoresData) ? riskScoresData : []);
        setRealTimeAlerts(Array.isArray(alertsData) ? alertsData : []);

        analyzeThreatLogs(Array.isArray(threatLogsData) ? threatLogsData.map(item => item.log) : []);
        analyzeAlerts(Array.isArray(alertsData) ? alertsData.map(item => item.alert) : []);
      } catch (error) {
        console.error('Error fetching data:', error);
        setError(error.message);
        setThreatLogs([{ log: 'Hardcoded Threat Log 1', response_plan: {} }, { log: 'Hardcoded Threat Log 2', response_plan: {} }]);
        setRealTimeAlerts([{ alert: 'Hardcoded Alert 1', response_plan: {} }, { alert: 'Hardcoded Alert 2', response_plan: {} }]);
        setRiskScores([50, 75, 90]);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  useEffect(() => {
    if (riskScores.length > 0) {
      const avg = riskScores.reduce((sum, score) => sum + score, 0) / riskScores.length;
      setAverageRiskScore(avg.toFixed(1));
      const highRisks = riskScores.filter((score) => score > 80).length;
      setHighRiskCount(highRisks);
    }
  }, [riskScores]);

  const analyzeThreatLogs = (logs) => {
    const categories = { Malware: 0, Phishing: 0, IP: 0, Other: 0 };
    logs.forEach((log) => {
      if (log.includes('Malware')) categories.Malware++;
      else if (log.includes('Phishing')) categories.Phishing++;
      else if (log.includes('IP')) categories.IP++;
      else categories.Other++;
    });
    setThreatCategories(categories);
  };

  const analyzeAlerts = (alerts) => {
    const types = { 'Suspicious login': 0, Malware: 0, 'Unusual traffic': 0, Other: 0 };
    alerts.forEach((alert) => {
      if (alert.includes('Suspicious login')) types['Suspicious login']++;
      else if (alert.includes('malware')) types['Malware']++;
      else if (alert.includes('traffic')) types['Unusual traffic']++;
      else types['Other']++;
    });
    setAlertsByType(types);
  };

  const filteredThreatLogs =
    selectedThreat === 'All' ? threatLogs : threatLogs.filter((item) => item.log.includes(selectedThreat));

  return (
    <div className="dashboard-container">
      <h1>Security Intelligence Dashboard</h1>

      {loading ? (
        <div className="loading-spinner">Loading dashboard data...</div>
      ) : error ? (
        <div className="error-message">
          <p>Error: {error}</p>
          <button onClick={() => window.location.reload()}>Retry</button>
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
                  backgroundColor: averageRiskScore > 80 ? 'red' : averageRiskScore > 60 ? 'orange' : 'green',
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
                {filteredThreatLogs.length > 0 ? (
                  filteredThreatLogs.map((item, index) => (
                    <li
                      key={index}
                      className={
                        item.log.includes('Malware')
                          ? 'threat-malware'
                          : item.log.includes('Phishing')
                          ? 'threat-phishing'
                          : 'threat-ip'
                      }
                    >
                      <div className="threat-log">
                        <strong>{item.log}</strong>
                        {item.response_plan && (
                          <div className="response-plan">
                            <h4>Response Plan (Priority: {item.response_plan.priority})</h4>
                            <p><strong>Type:</strong> {item.response_plan.threat_type}</p>
                            <p><strong>Description:</strong> {item.response_plan.description}</p>
                            <h5>Mitigation Strategies:</h5>
                            <ul>
                              {item.response_plan.mitigation_strategies.map((strategy, idx) => (
                                <li key={idx}>{strategy}</li>
                              ))}
                            </ul>
                            <h5>Response Steps:</h5>
                            <ol>
                              {item.response_plan.response_steps.map((step, idx) => (
                                <li key={idx}>{step}</li>
                              ))}
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
                        item.alert.includes('Suspicious login')
                          ? 'alert-login'
                          : item.alert.includes('malware')
                          ? 'alert-malware'
                          : item.alert.includes('traffic')
                          ? 'alert-traffic'
                          : 'alert-other'
                      }
                    >
                      <div className="alert-item">
                        <strong>{item.alert}</strong>
                        <span className="alert-time">{new Date().toLocaleTimeString()}</span>
                        {item.response_plan && (
                          <div className="response-plan">
                            <h4>Response Plan (Priority: {item.response_plan.priority})</h4>
                            <p><strong>Type:</strong> {item.response_plan.threat_type}</p>
                            <p><strong>Description:</strong> {item.response_plan.description}</p>
                            <h5>Mitigation Strategies:</h5>
                            <ul>
                              {item.response_plan.mitigation_strategies.map((strategy, idx) => (
                                <li key={idx}>{strategy}</li>
                              ))}
                            </ul>
                            <h5>Response Steps:</h5>
                            <ol>
                              {item.response_plan.response_steps.map((step, idx) => (
                                <li key={idx}>{step}</li>
                              ))}
                            </ol>
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
  );
}

export default Dashboard;