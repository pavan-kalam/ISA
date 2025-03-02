// src/frontend/src/components/Shodan.js
import React, { useState } from 'react';
import API_KEYS from './config.js';

function Shodan() {
    const [query, setQuery] = useState('');
    const [result, setResult] = useState(null);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setResult(null);

        const response = await fetch(`http://localhost:5001/api/shodan?query=${encodeURIComponent(query)}`, {
            method: 'GET',
            headers: {
                'API-Key': API_KEYS.shodan, // Replace with your actual API key
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
            <h2>Shodan Search</h2>
            <form onSubmit={handleSubmit}>
                <input
                    type="text"
                    placeholder="Enter search query"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    required
                />
                <button type="submit">Search</button>
            </form>
            {error && <p style={{ color: 'red' }}>{error}</p>}
            {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
        </div>
    );
}

export default Shodan;