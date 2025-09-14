import { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './RegisterPage.css';

function RegisterPage() {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    password_confirmation: '',
    sponsor_email: '',
    role: 'employee',
  });
  const [mfaCode, setMfaCode] = useState('');
  const [step, setStep] = useState('register');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      await axios.post('http://localhost:5000/api/register', formData);
      localStorage.setItem('registration_data', JSON.stringify(formData));
      setStep('mfa');
      setError('');
      setSuccess('MFA code sent to your email.');
    } catch (err) {
      setError(err.response?.data?.message || 'Registration failed');
      setSuccess('');
    }
  };

  const handleMfa = async (e) => {
    e.preventDefault();
    try {
      await axios.post('http://localhost:5000/api/verify_registration_mfa', { ...formData, mfa_code: mfaCode });
      localStorage.removeItem('registration_data');
      setSuccess('Registration submitted. Awaiting sponsor approval.');
      setError('');
      setTimeout(() => navigate('/'), 3000);
    } catch (err) {
      setError(err.response?.data?.message || 'MFA verification failed');
      setSuccess('');
    }
  };

  return (
    <div className="register-container">
      <div className="register-card">
        {step === 'register' ? (
          <form onSubmit={handleRegister} className="form">
            <h2 className="form-title">Register</h2>
            <div className="form-group">
              <label htmlFor="username" className="form-label">Username</label>
              <input
                type="text"
                name="username"
                value={formData.username}
                onChange={handleChange}
                className="form-input"
                placeholder="Enter your username"
                required
              />
            </div>
            <div className="form-group">
              <label htmlFor="email" className="form-label">Email</label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                className="form-input"
                placeholder="Enter your email"
                required
              />
            </div>
            <div className="form-group">
              <label htmlFor="password" className="form-label">Password</label>
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                className="form-input"
                placeholder="Enter your password"
                required
              />
            </div>
            <div className="form-group">
              <label htmlFor="password_confirmation" className="form-label">Confirm Password</label>
              <input
                type="password"
                name="password_confirmation"
                value={formData.password_confirmation}
                onChange={handleChange}
                className="form-input"
                placeholder="Confirm your password"
                required
              />
            </div>
            <div className="form-group">
              <label htmlFor="sponsor_email" className="form-label">Sponsor Email</label>
              <input
                type="email"
                name="sponsor_email"
                value={formData.sponsor_email}
                onChange={handleChange}
                className="form-input"
                placeholder="Enter sponsor email"
                required
              />
            </div>
            <div className="form-group">
              <label htmlFor="role" className="form-label">Role</label>
              <select
                name="role"
                value={formData.role}
                onChange={handleChange}
                className="form-input"
                required
              >
                <option value="employee">Employee</option>
                <option value="hr">HR</option>
                <option value="it">IT</option>
              </select>
            </div>
            <button type="submit" className="form-button">Register</button>
            <p className="form-link">
              Already have an account?{' '}
              <a href="/" className="link">Login</a>
            </p>
            {error && <p className="error-message">{error}</p>}
            {success && <p className="success-message">{success}</p>}
          </form>
        ) : (
          <form onSubmit={handleMfa} className="form">
            <h2 className="form-title">Enter MFA Code</h2>
            <div className="form-group">
              <label htmlFor="mfaCode" className="form-label">MFA Code</label>
              <input
                type="text"
                name="mfaCode"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                className="form-input"
                placeholder="Enter MFA code"
                required
              />
            </div>
            <button type="submit" className="form-button">Verify</button>
            {error && <p className="error-message">{error}</p>}
            {success && <p className="success-message">{success}</p>}
          </form>
        )}
      </div>
    </div>
  );
}

export default RegisterPage;