// src/frontend/src/components/AbuseIPDB.js
import React, { useState } from 'react';
import API_KEYS from './config.js';

function AbuseIPDB() {
    const [ip, setIp] = useState('');
    const [result, setResult] = useState(null);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setResult(null);

        const response = await fetch(`http://localhost:5001/api/abuseipdb?ip_address=${encodeURIComponent(ip)}`, {
            method: 'GET',
            headers: {
                'API-Key': API_KEYS.abuseipdb, // Replace with your actual API key
            },
        });

        if (response.ok) {
            const data = await response.json();
            setResult(data);
        } else {
            const errorData = await response.json();
            setError(errorData.error);
        }
    };

    return (
        <div>
            <h2>AbuseIPDB IP Check</h2>
            <form onSubmit={handleSubmit}>
                <input
                    type="text"
                    placeholder="Enter IP Address"
                    value={ip}
                    onChange={(e) => setIp(e.target.value)}
                    required
                />
                <button type="submit">Check IP</button>
            </form>
            {error && <p style={{ color: 'red' }}>{error}</p>}
            {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
        </div>
    );
}

export default AbuseIPDB;