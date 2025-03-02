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


// // src/frontend/src/components/Login.js
// import React, { useState } from 'react';

// const users = []; // In-memory user storage (for demonstration purposes)

// function Login({ onLogin }) {
//     const [email, setEmail] = useState('');
//     const [password, setPassword] = useState('');
//     const [error, setError] = useState('');
//     const [isRegistering, setIsRegistering] = useState(false);

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
//                 onLogin(); // Call the onLogin function to update authentication state
//                 // navigate('/dashboard'); // Redirect to the dashboard
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


// // src/frontend/src/components/Login.js
// import React, { useState } from 'react';
// import { useNavigate } from 'react-router-dom'; // Import useNavigate instead of useHistory

// function Login({ onLogin }) {
//   const [username, setUsername] = useState('');
//   const [password, setPassword] = useState('');
//   const [message, setMessage] = useState('');
//   const navigate = useNavigate(); // Initialize useNavigate

//   const handleLogin = async (e) => {
//     e.preventDefault();
//     const response = await fetch('http://localhost:5001/api/login', {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//       },
//       body: JSON.stringify({ username, password }),
//     });

//     const data = await response.json();
//     if (response.ok) {
//       onLogin(data); // Pass user data to parent component
//     } else {
//       setMessage(data.error);
//     }
//   };

//   const handleCreateAccount = () => {
//     navigate('/register'); // Navigate to the registration page
//   };

//   return (
//     <div>
//       <h2>Login</h2>
//       <form onSubmit={handleLogin}>
//         <input
//           type="text"
//           placeholder="Username"
//           value={username}
//           onChange={(e) => setUsername(e.target.value)}
//           required
//         />
//         <input
//           type="password"
//           placeholder="Password"
//           value={password}
//           onChange={(e) => setPassword(e.target.value)}
//           required
//         />
//         <button type="submit">Login</button>
//       </form>
//       {message && <p>{message}</p>}
//       <p>
//         Don't have an account?{' '}
//         <button onClick={handleCreateAccount}>Create Account</button>
//       </p>
//     </div>
//   );
// }

// export default Login;



// src/frontend/src/components/Login.js
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './Login.css'; // Make sure to create this CSS file

function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const response = await fetch('http://localhost:5001/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });
      
      const data = await response.json();
      
      if (response.ok) {
        onLogin(data); // Pass user data to parent component
        navigate('/dashboard'); // Automatically redirect to dashboard
      } else {
        setMessage(data.error || 'Login failed. Please try again.');
      }
    } catch (error) {
      setMessage('Network error. Please try again later.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCreateAccount = () => {
    navigate('/register');
  };

  const handleForgotPassword = () => {
    navigate('/forgot-password');
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <h1>Welcome Back</h1>
          <p>Sign in to access your dashboard</p>
        </div>
        
        {message && (
          <div className="error-message">
            <span className="error-icon">!</span>
            {message}
          </div>
        )}
        
        <form onSubmit={handleLogin}>
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <div className="input-container">
              <span className="input-icon user-icon"></span>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                required
              />
            </div>
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <div className="input-container">
              <span className="input-icon password-icon"></span>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                required
              />
            </div>
          </div>
          
          <div className="login-options">
            <div className="remember-me">
              <input
                id="remember_me"
                name="remember_me"
                type="checkbox"
              />
              <label htmlFor="remember_me">Remember me</label>
            </div>
            
            <button 
              type="button" 
              className="forgot-password"
              onClick={handleForgotPassword}
            >
              Forgot password?
            </button>
          </div>
          
          <button
            type="submit"
            disabled={isLoading}
            className="login-button"
          >
            {isLoading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
        
        <div className="create-account">
          <p>
            Don't have an account?{' '}
            <button
              type="button"
              onClick={handleCreateAccount}
              className="create-account-link"
            >
              Create Account
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}

export default Login;