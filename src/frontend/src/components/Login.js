// // 

// import React, { useState } from 'react';
// import { useNavigate } from 'react-router-dom'; // Import useNavigate for redirection

// const users = []; // In-memory user storage (for demonstration purposes)

// function Login() {
//     const [email, setEmail] = useState('');
//     const [password, setPassword] = useState('');
//     const [error, setError] = useState('');
//     const [isRegistering, setIsRegistering] = useState(false);
//     const navigate = useNavigate(); // Initialize useNavigate

//     const handleSubmit = (e) => {
//         e.preventDefault();
//         if (isRegistering) {
//             // Register new user
//             if (users.find(user => user.email === email)) {
//                 setError('User  already exists.');
//                 return;
//             }
//             users.push({ email, password });
//             alert('Account created successfully! You can now log in.');
//             setIsRegistering(false);
//         } else {
//             // Login existing user
//             const user = users.find(user => user.email === email && user.password === password);
//             if (user) {
//                 alert('Login successful!');
//                 navigate('/dashboard'); // Redirect to the dashboard
//             } else {
//                 setError('Invalid email or password.');
//             }
//         }
//         // Reset the form
//         setEmail('');
//         setPassword('');
//     };

//     return (
//         <div>
//             <h1>{isRegistering ? 'Create Account' : 'Login'}</h1>
//             {error && <p style={{ color: 'red' }}>{error}</p>}
//             <form onSubmit={handleSubmit}>
//                 <div>
//                     <label>Email:</label>
//                     <input 
//                         type="email" 
//                         value={email} 
//                         onChange={(e) => setEmail(e.target.value)} 
//                         required 
//                     />
//                 </div>
//                 <div>
//                     <label>Password:</label>
//                     <input 
//                         type="password" 
//                         value={password} 
//                         onChange={(e) => setPassword(e.target.value)} 
//                         required 
//                     />
//                 </div>
//                 <button type="submit">{isRegistering ? 'Create Account' : 'Login'}</button>
//             </form>
//             <p>
//                 {isRegistering ? 'Already have an account? ' : 'Don\'t have an account? '}
//                 <button onClick={() => setIsRegistering(!isRegistering)}>
//                     {isRegistering ? 'Login' : 'Create Account'}
//                 </button>
//             </p>
//         </div>
//     );
// }

// export default Login;


// src/frontend/src/components/Login.js
import React, { useState } from 'react';

const users = []; // In-memory user storage (for demonstration purposes)

function Login({ onLogin }) {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [isRegistering, setIsRegistering] = useState(false);

    const handleSubmit = (e) => {
        e.preventDefault();
        if (isRegistering) {
            // Register new user
            if (users.find(user => user.email === email)) {
                setError('User  already exists.');
                return;
            }
            users.push({ email, password });
            alert('Account created successfully! You can now log in.');
            setIsRegistering(false);
        } else {
            // Login existing user
            const user = users.find(user => user.email === email && user.password === password);
            if (user) {
                alert('Login successful!');
                onLogin(); // Call the onLogin function to update authentication state
                // navigate('/dashboard'); // Redirect to the dashboard
            } else {
                setError('Invalid email or password.');
            }
        }
        // Reset the form
        setEmail('');
        setPassword('');
    };

    return (
        <div>
            <h1>{isRegistering ? 'Create Account' : 'Login'}</h1>
            {error && <p style={{ color: 'red' }}>{error}</p>}
            <form onSubmit={handleSubmit}>
                <div>
                    <label>Email:</label>
                    <input 
                        type="email" 
                        value={email} 
                        onChange={(e) => setEmail(e.target.value)} 
                        required 
                    />
                </div>
                <div>
                    <label>Password:</label>
                    <input 
                        type="password" 
                        value={password} 
                        onChange={(e) => setPassword(e.target.value)} 
                        required 
                    />
                </div>
                <button type="submit">{isRegistering ? 'Create Account' : 'Login'}</button>
            </form>
            <p>
                {isRegistering ? 'Already have an account? ' : 'Don\'t have an account? '}
                <button onClick={() => setIsRegistering(!isRegistering)}>
                    {isRegistering ? 'Login' : 'Create Account'}
                </button>
            </p>
        </div>
    );
}

export default Login;