import { useState, useEffect } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';
import './SignatureForm.css';

function SignatureForm() {
  const [signingUrl, setSigningUrl] = useState('');
  const [error, setError] = useState('');
  const [username, setUsername] = useState('');
  const { envelopeId } = useParams();
  const navigate = useNavigate();
  const [activeSection, setActiveSection] = useState('Signature');
  const role = localStorage.getItem('role');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = localStorage.getItem('access_token');
        if (!token) {
          setError('No authentication token found');
          navigate('/');
          return;
        }

        // Fetch user data for username
        const userResponse = await axios.get('http://localhost:5000/api/protected', {
          headers: { Authorization: `Bearer ${token}` },
        });
        setUsername(userResponse.data.username || 'User');

        // Fetch signing URL
        const response = await axios.post(
          'http://localhost:5000/api/get_signing_url',
          { envelope_id: envelopeId },
          { headers: { Authorization: `Bearer ${token}` } }
        );
        setSigningUrl(response.data.signing_url);
      } catch (err) {
        setError(err.response?.data?.message || 'Failed to load signing URL');
        if (err.response?.status === 401 || err.response?.status === 403) {
          localStorage.removeItem('access_token');
          localStorage.removeItem('role');
          navigate('/');
        }
      }
    };
    fetchData();
  }, [envelopeId, navigate]);

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('role');
    navigate('/');
  };

  return (
    <div className="dashboard-container">
      <div className="sidebar">
        <h2 className="sidebar-header">Dashboard</h2>
        <div
          className={`nav-item ${activeSection === 'Users' ? 'active' : ''}`}
          onClick={() => navigate('/dashboard')}
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="nav-icon"
          >
            <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
            <circle cx="9" cy="7" r="4" />
            <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
            <path d="M16 3.13a4 4 0 0 1 0 7.75" />
          </svg>
          <span>Users</span>
        </div>
        <div
          className={`nav-item ${activeSection === 'Tasks' ? 'active' : ''}`}
          onClick={() => navigate('/dashboard')}
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="nav-icon"
          >
            <rect width="8" height="4" x="8" y="2" rx="1" ry="1" />
            <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" />
            <path d="M12 11h4" />
            <path d="M12 16h4" />
            <path d="M8 11h.01" />
            <path d="M8 16h.01" />
          </svg>
          <span>Tasks</span>
        </div>
        <div
          className={`nav-item ${activeSection === 'Settings' ? 'active' : ''}`}
          onClick={() => navigate('/dashboard')}
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="nav-icon"
          >
            <path d="M9.671 4.136a2.34 2.34 0 0 1 4.659 0 2.34 2.34 0 0 0 3.319 1.915 2.34 2.34 0 0 1 2.33 4.033 2.34 2.34 0 0 0 0 3.831 2.34 2.34 0 0 1-2.33 4.033 2.34 2.34 0 0 0-3.319 1.915 2.34 2.34 0 0 1-4.659 0 2.34 2.34 0 0 0-3.32-1.915 2.34 2.34 0 0 1-2.33-4.033 2.34 2.34 0 0 0 0-3.831A2.34 2.34 0 0 1 6.35 6.051a2.34 2.34 0 0 0 3.319-1.915" />
            <circle cx="12" cy="12" r="3" />
          </svg>
          <span>Settings</span>
        </div>
        <button onClick={handleLogout} className="logout-btn">
          Logout
        </button>
      </div>
      <div className="content-area">
        <div className="content-header">
          <h1 className="content-title">Review and Sign Policies</h1>
          <p className="content-subtitle">Role: {role?.toUpperCase() || 'EMPLOYEE'}</p>
        </div>
        {error && <p className="error-message">{error}</p>}
        <div className="section">
          <div className="card user-management">
            <h2 className="card-title-large">Sign Policy</h2>
            <p className="text-lg mb-6">
              Please review and sign the company policy document below using the DocuSign interface.
              Follow the prompts to complete your electronic signature. Ensure you read all terms carefully before signing.
              If you encounter issues, contact HR for assistance.
            </p>
            {error ? (
              <p className="text-red-500 text-center">{error}</p>
            ) : !signingUrl ? (
              <p className="text-gray-700 text-center">Loading signing form...</p>
            ) : (
              <div className="iframe-wrapper">
                <iframe
                  src={signingUrl}
                  title="DocuSign Signing"
                  className="w-full h-full border rounded-md"
                />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default SignatureForm;