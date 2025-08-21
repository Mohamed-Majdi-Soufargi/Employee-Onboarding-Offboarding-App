import { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function RegisterPage() {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    password_confirmation: '',
    sponsor_email: '',
    role: 'employee'
  });
  const [mfaCode, setMfaCode] = useState('');
  const [step, setStep] = useState('register');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('/api/register', formData);
      setStep('mfa');
      setError('');
      if (response.data.mfa_code) {
        console.log(`MFA code for testing: ${response.data.mfa_code}`);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Registration failed');
    }
  };

  const handleMfa = async (e) => {
    e.preventDefault();
    try {
      await axios.post('/api/verify_registration_mfa', { ...formData, mfa_code: mfaCode });
      setError('');
      alert('Registration submitted. Awaiting sponsor approval.');
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.message || 'MFA verification failed');
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <div className="bg-white p-8 rounded-lg shadow-md w-full max-w-md">
        {step === 'register' ? (
          <form onSubmit={handleRegister}>
            <h2 className="text-2xl font-bold mb-6 text-center">Register</h2>
            <div className="mb-4">
              <label className="block text-gray-700 mb-2" htmlFor="username">Username</label>
              <input
                type="text"
                name="username"
                value={formData.username}
                onChange={handleChange}
                className="w-full p-2 border rounded-md"
                placeholder="Username"
                required
              />
            </div>
            <div className="mb-4">
              <label className="block text-gray-700 mb-2" htmlFor="email">Email</label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                className="w-full p-2 border rounded-md"
                placeholder="Email"
                required
              />
            </div>
            <div className="mb-4">
              <label className="block text-gray-700 mb-2" htmlFor="password">Password</label>
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                className="w-full p-2 border rounded-md"
                placeholder="Password"
                required
              />
            </div>
            <div className="mb-4">
              <label className="block text-gray-700 mb-2" htmlFor="password_confirmation">Confirm Password</label>
              <input
                type="password"
                name="password_confirmation"
                value={formData.password_confirmation}
                onChange={handleChange}
                className="w-full p-2 border rounded-md"
                placeholder="Confirm Password"
                required
              />
            </div>
            <div className="mb-4">
              <label className="block text-gray-700 mb-2" htmlFor="sponsor_email">Sponsor Email</label>
              <input
                type="email"
                name="sponsor_email"
                value={formData.sponsor_email}
                onChange={handleChange}
                className="w-full p-2 border rounded-md"
                placeholder="Sponsor Email"
                required
              />
            </div>
            <div className="mb-6">
              <label className="block text-gray-700 mb-2" htmlFor="role">Role</label>
              <select
                name="role"
                value={formData.role}
                onChange={handleChange}
                className="w-full p-2 border rounded-md"
                required
              >
                <option value="employee">Employee</option>
                <option value="hr">HR</option>
                <option value="it">IT</option>
              </select>
            </div>
            <button
              type="submit"
              className="w-full bg-blue-500 text-white p-2 rounded-md hover:bg-blue-600"
            >
              Register
            </button>
            <p className="mt-4 text-center">
              Already have an account?{' '}
              <a href="/" className="text-blue-500 hover:underline">Login</a>
            </p>
            {error && <p className="mt-4 text-red-500 text-center">{error}</p>}
          </form>
        ) : (
          <form onSubmit={handleMfa}>
            <h2 className="text-2xl font-bold mb-6 text-center">Enter MFA Code</h2>
            <div className="mb-4">
              <label className="block text-gray-700 mb-2" htmlFor="mfaCode">MFA Code</label>
              <input
                type="text"
                name="mfaCode"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                className="w-full p-2 border rounded-md"
                placeholder="MFA Code"
                required
              />
            </div>
            <button
              type="submit"
              className="w-full bg-blue-500 text-white p-2 rounded-md hover:bg-blue-600"
            >
              Verify
            </button>
            {error && <p className="mt-4 text-red-500 text-center">{error}</p>}
          </form>
        )}
      </div>
    </div>
  );
}

export default RegisterPage;