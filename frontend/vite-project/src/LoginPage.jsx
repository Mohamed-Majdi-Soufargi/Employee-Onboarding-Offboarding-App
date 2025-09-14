import { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './LoginPage.css';

function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [step, setStep] = useState('login');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      await axios.post('http://localhost:5000/api/login', { username, password });
      setStep('mfa');
      setError('');
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed');
    }
  };

  const handleMfa = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:5000/api/verify_mfa', { username, mfa_code: mfaCode });
      localStorage.setItem('access_token', response.data.access_token);
      localStorage.setItem('role', response.data.role || 'employee');
      navigate('/dashboard');
    } catch (err) {
      setError(err.response?.data?.message || 'MFA verification failed');
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        {step === 'login' ? (
          <form onSubmit={handleLogin} className="form">
            <h2 className="form-title">Login</h2>
            <div className="form-group">
              <label htmlFor="username" className="form-label">Username</label>
              <input
                type="text"
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="form-input"
                placeholder="Enter your username"
                required
              />
            </div>
            <div className="form-group">
              <label htmlFor="password" className="form-label">Password</label>
              <input
                type="password"
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="form-input"
                placeholder="Enter your password"
                required
              />
            </div>
            <button type="submit" className="form-button">Login</button>
            <p className="form-link">
              Don’t have an account?{' '}
              <a href="/register" className="link">Register</a>
            </p>
            {error && <p className="error-message">{error}</p>}
          </form>
        ) : (
          <form onSubmit={handleMfa} className="form">
            <h2 className="form-title">Enter MFA Code</h2>
            <div className="form-group">
              <label htmlFor="mfaCode" className="form-label">MFA Code</label>
              <input
                type="text"
                id="mfaCode"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                className="form-input"
                placeholder="Enter MFA code"
                required
              />
            </div>
            <button type="submit" className="form-button">Verify</button>
            {error && <p className="error-message">{error}</p>}
          </form>
        )}
      </div>
    </div>
  );
}

export default LoginPage;