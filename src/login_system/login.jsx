import React, { useState } from 'react';
import './login.css';



const Login = () => {
        const [username, setUsername] = useState('');
        const [password, setPassword] = useState('');
        const [role, setRole] = useState('');
        const [error, setError] = useState('');

        const handleLogin = async () => {
            try {
                const response = await fetch('https://api.example.com/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password }),
                });
    
                if (response.ok) {
                    // Login successful
                    setError('');
                    // Redirect to the home page or do something else
                } else {
                    // Login failed
                    setError('Falscher Benutzername oder Passwort');
                    
                }
            } catch (error) {
                console.error('Error:', error);
                setError('Es ist ein Fehler aufgetreten');
            }
        };

        const handleRegister = async () => {
            if (role !== 'teacher' && role !== 'student') {
                setError('Invalid user role');
                return;
            }

            try {
                const response = await fetch('https://api.example.com/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password, role }),
                });

                if (response.ok) {
                    // Registration successful
                    setError('');
                    // Redirect to the login page or do something else
                } else {
                    // Registration failed
                    setError('Registrierung fehlgeschlagen');
                }
            } catch (error) {
                console.error('Error:', error);
                setError('Es ist ein Fehler aufgetreten');
            }
        };

        return (
            <div>
                <h1>Login</h1>
                {error && <p>{error}</p>}
                <input
                    type="text"
                    placeholder="Benutzername"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                />
                <input
                    type="password"
                    placeholder="Passwort"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                />
                <select value={role} onChange={(e) => setRole(e.target.value)}>
                    <option value="">Rolle Auswälen</option>
                    <option value="teacher">Lehrer</option>
                    <option value="student">Schüler</option>
                </select>
                <button onClick={handleLogin}>Login</button>
                <button onClick={handleRegister}>Register</button>
            </div>
        );
};

export default Login;