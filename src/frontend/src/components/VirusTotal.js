// src/frontend/src/components/VirusTotal.js
import React, { useState } from 'react';

function VirusTotal() {
    const [url, setUrl] = useState('');
    const [result, setResult] = useState(null);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setResult(null);

        const response = await fetch(`http://localhost:5001/api/virustotal?url=${encodeURIComponent(url)}`, {
            method: 'GET',
            headers: {
                'API-Key': '4f931f13f341ec0f9a2089984b43523a98dfa79689b8117e7449196afbdec9f', // Replace with your actual API key
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
            <h2>VirusTotal URL Check</h2>
            <form onSubmit={handleSubmit}>
                <input
                    type="text"
                    placeholder="Enter URL"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    required
                />
                <button type="submit">Check URL</button>
            </form>
            {error && <p style={{ color: 'red' }}>{error}</p>}
            {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
        </div>
    );
}

export default VirusTotal;