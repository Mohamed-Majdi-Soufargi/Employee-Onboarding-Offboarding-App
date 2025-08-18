import React, { useState } from 'react';
import './loginpage.css';

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!email || !password) {
      setError('Please fill in all fields.');
    } else {
      setError('');
      // Add your login logic here
      console.log('Login attempted with:', { email, password });
    }
  };

  return (
    <div className="login-container">
      <div className="logo">∞</div>
      <h2 id="login-label" className="fade-in">Onboarding Login Page</h2>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="email">Username / Email</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Enter your email"
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter your password"
            required
          />
        </div>
        {error && <p className="error-message">{error}</p>}
        <button type="submit" className="btn-slide">
          Sign In
        </button>
      </form>
    </div>
  );
}

export default App;