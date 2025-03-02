// // src/frontend/src/components/HIBP.js
// import React, { useState } from 'react';

// function HIBP() {
//     const [email, setEmail] = useState('');
//     const [result, setResult] = useState(null);
//     const [error, setError] = useState('');

//     const handleSubmit = async (e) => {
//         e.preventDefault();
//         setError('');
//         setResult(null);

//         const response = await fetch(`http://localhost:5001/api/hibp?email=${encodeURIComponent(email)}`, {
//             method: 'GET',
//         });

//         if (response.ok) {
//             const data = await response.json();
//             setResult(data);
//         } else {
//             const errorData = await response.json();
//             setError(errorData.error);
//         }
//     };

//     return (
//         <div>
//             <h2>Have I Been Pwned Check</h2>
//             <form onSubmit={handleSubmit}>
//                 <input
//                     type="email"
//                     placeholder="Enter Email Address"
//                     value={email}
//                     onChange={(e) => setEmail(e.target.value)}
//                     required
//                 />
//                 <button type="submit">Check Email</button>
//             </form>
//             {error && <p style={{ color: 'red' }}>{error}</p>}
//             {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
//         </div>
//     );
// }

// export default HIBP;



// src/frontend/src/components/HIBP.js
import React, { useState } from 'react';
import './HIBP.css'; // You'll need to create this CSS file

function HIBP() {
  const [email, setEmail] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setResult(null);
    setLoading(true);
    
    try {
      const response = await fetch(`http://localhost:5001/api/hibp?email=${encodeURIComponent(email)}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setResult(data);
      } else {
        const errorData = await response.text();
        try {
          const parsedError = JSON.parse(errorData);
          setError(parsedError.error || 'An error occurred while checking this email');
        } catch (e) {
          setError(`Error: ${response.status} - ${response.statusText || 'Unknown error'}`);
        }
      }
    } catch (err) {
      console.error('HIBP check error:', err);
      setError(`Failed to connect to the server. Please check your connection and try again.`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="hibp-container">
      <h2>Have I Been Pwned Check</h2>
      <form onSubmit={handleSubmit} className="hibp-form">
        <input
          type="email"
          placeholder="Enter Email Address"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          className="hibp-input"
        />
        <button type="submit" className="hibp-button" disabled={loading}>
          {loading ? 'Checking...' : 'Check Email'}
        </button>
      </form>
      
      {loading && <div className="hibp-loading">Checking email against breach databases...</div>}
      
      {error && (
        <div className="hibp-error">
          <p>{error}</p>
        </div>
      )}
      
      {result && (
        <div className="hibp-result">
          <h3>Results for {email}</h3>
          {Array.isArray(result) && result.length > 0 ? (
            <div>
              <p className="hibp-found">This email appears in {result.length} data breaches:</p>
              <ul className="hibp-breach-list">
                {result.map((breach, index) => (
                  <li key={index} className="hibp-breach-item">
                    <strong>{breach.Name}</strong> (Breach date: {new Date(breach.BreachDate).toLocaleDateString()})
                    <p>Compromised data: {breach.DataClasses.join(', ')}</p>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="hibp-not-found">Good news! No breaches found for this email.</p>
          )}
        </div>
      )}
    </div>
  );
}

export default HIBP;