import React, { useState } from 'react';

function ThreatDashboard() {
    const [assets, setAssets] = useState([]);
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [riskScores, setRiskScores] = useState([]);
    const [threatLogs, setThreatLogs] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [activeApi, setActiveApi] = useState(null);

    const fetchData = async (api) => {
        setLoading(true);
        setError(null);
        try {
            const response = await fetch(`http://localhost:5001/api/${api}`);
            if (!response.ok) {
                throw new Error('Failed to fetch data');
            }
            const data = await response.json();
            switch (api) {
                case 'assets':
                    setAssets(data);
                    break;
                case 'vulnerabilities':
                    setVulnerabilities(data);
                    break;
                case 'threatLogs':
                    setThreatLogs(data);
                    break;
                case 'riskScores':
                    setRiskScores(data);
                    break;
                default:
                    break;
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleAPIClick = (api) => {
        setActiveApi(api);
        fetchData(api);
    };

    if (loading) return <div>Loading...</div>;
    if (error) return <div>Error: {error}</div>;

    return (
        <div className="p-4">
            <h1 className="text-2xl font-bold">Threat Dashboard</h1>
            <div className="mt-4">
                <button onClick={() => handleAPIClick('assets')} className="mr-2">Fetch Assets</button>
                <button onClick={() => handleAPIClick('vulnerabilities')} className="mr-2">Fetch Vulnerabilities</button>
                <button onClick={() => handleAPIClick('threatLogs')} className="mr-2">Fetch Threat Logs</button>
                <button onClick={() => handleAPIClick('riskScores')} className="mr-2">Fetch Risk Scores</button>
            </div>
            {activeApi === 'assets' && (
                <div>
                    <h2 className="text-xl mt-4">Asset Inventory</h2>
                    <ul>
                        {assets.map(asset => (
                            <li key={asset.id}>{asset.name}</li>
                        ))}
                    </ul>
                </div>
            )}
            {activeApi === 'vulnerabilities' && (
                <div>
                    <h2 className="text-xl mt-4">Threat-Vulnerability Mappings</h2>
                    <ul>
                        {vulnerabilities.map(vuln => (
                            <li key={vuln.id}>{vuln.description}</li>
                        ))}
                    </ul>
                </div>
            )}
            {activeApi === 'threatLogs' && (
                <div>
                    <h2 className="text-xl mt-4">Threat Logs</h2>
                    <ul>
                        {threatLogs.map((log, index) => (
                            <li key={index}>{log.event} - Risk Level: {log.risk}</li>
                        ))}
                    </ul>
                </div>
            )}
            {activeApi === 'riskScores' && (
                <div>
                    <h2 className="text-xl mt-4">Risk Scores</h2>
                    <ul>
                        {riskScores.map(score => (
                            <li key={score.id}>{score.value}</li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    );
}

export default ThreatDashboard;
