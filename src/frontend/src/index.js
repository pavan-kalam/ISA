// // src/frontend/src/index.js
// import React from 'react';
// import ReactDOM from 'react-dom';
// import App from './App';
// import './styles.css'; // Import the CSS file

// ReactDOM.render(
//     <React.StrictMode>
//         <App />
//     </React.StrictMode>,
//     document.getElementById('root')
// );

// src/frontend/src/index.js
import React from 'react';
import ReactDOM from 'react-dom/client'; // Change this line
import App from './App';
import './styles.css'; // Import your CSS file

// Create a root for the application
const root = ReactDOM.createRoot(document.getElementById('root'));

// Render the App component
root.render(
    <React.StrictMode>
        <App />
    </React.StrictMode>
);