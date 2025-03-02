// // src/frontend/src/App.js
// import React from 'react';
// import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
// import Home from './components/Home';
// import Login from './components/Login';
// import Dashboard from './components/Dashboard';
// import Navbar from './components/Navbar';

// function App() {
//     return (
//         <Router>
//             <Navbar />
//             <Routes>
//                 <Route path="/" element={<Home />} />
//                 <Route path="/login" element={<Login />} />
//                 <Route path="/dashboard" element={<Dashboard />} />
//             </Routes>
//         </Router>
//     );
// }

// export default App;



// // src/frontend/src/App.js
// import React, { useState } from 'react';
// import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
// import Home from './components/Home';
// import Login from './components/Login';
// import Dashboard from './components/Dashboard';
// import Navbar from './components/Navbar';

// function App() {
//     const [isAuthenticated, setIsAuthenticated] = useState(false);

//     const handleLogin = () => {
//         setIsAuthenticated(true);
//     };

//     const handleLogout = () => {
//         setIsAuthenticated(false);
//     };

//     return (
//         <Router>
//             <Navbar onLogout={handleLogout} />
//             <Routes>
//                 <Route path="/" element={<Home />} />
//                 <Route path="/login" element={<Login onLogin={handleLogin} />} />
//                 <Route path="/dashboard" element={isAuthenticated ? <Dashboard /> : <Navigate to="/login" />} />
//             </Routes>
//         </Router>
//     );
// }

// export default App;



// src/frontend/src/App.js
import React, { useState } from 'react';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import Home from './components/Home';
import Login from './components/Login';
import Register from './components/Register'; // Import the Register component
import Dashboard from './components/Dashboard';
import Navbar from './components/Navbar';

function App() {
    const [isAuthenticated, setIsAuthenticated] = useState(false);

    const handleLogin = () => {
        setIsAuthenticated(true);
    };

    const handleLogout = () => {
        setIsAuthenticated(false);
    };

    return (
        <Router>
            <Navbar onLogout={handleLogout} />
            <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/login" element={<Login onLogin={handleLogin} />} />
                <Route path="/register" element={<Register />} /> {/* Add the Register route */}
                <Route path="/dashboard" element={isAuthenticated ? <Dashboard /> : <Navigate to="/login" />} />
            </Routes>
        </Router>
    );
}

export default App;