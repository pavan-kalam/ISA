// // src/frontend/src/components/Navbar.js
// import React from 'react';
// import { Link } from 'react-router-dom';

// function Navbar() {
//     return (
//         <nav>
//             <ul>
//                 <li><Link to="/">Home</Link></li>
//                 <li><Link to="/login">Login</Link></li>
//                 <li><Link to="/dashboard">Dashboard</Link></li>
//             </ul>
//         </nav>
//     );
// }

// export default Navbar;


// // src/frontend/src/components/Navbar.js
// import React from 'react';
// import { Link } from 'react-router-dom';

// function Navbar({ onLogout }) {
//     return (
//         <nav>
//             <ul>
//                 <li><Link to="/">Home</Link></li>
//                 <li><Link to="/login">Login</Link></li>
//                 <li><Link to="/dashboard">Dashboard</Link></li>
//                 <li><button onClick={onLogout}>Logout</button></li>
//             </ul>
//         </nav>
//     );
// }

// export default Navbar;


// src/frontend/src/components/Navbar.js
import React from 'react';
import { Link } from 'react-router-dom';

function Navbar({ onLogout }) {
    return (
        <nav>
            <ul>
                <li><Link to="/">Home</Link></li>
                {!onLogout ? ( // Check if the user is authenticated
                    <>
                        <li><Link to="/login">Login</Link></li>
                        <li><Link to="/register">Create Account</Link></li> {/* Add Create Account link */}
                    </>
                ) : (
                    <li><button onClick={onLogout}>Logout</button></li>
                )}
                <li><Link to="/dashboard">Dashboard</Link></li>
            </ul>
        </nav>
    );
}

export default Navbar;