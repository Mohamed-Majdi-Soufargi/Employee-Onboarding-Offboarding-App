import { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './Welcome.css';

function Welcome() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [retryCount, setRetryCount] = useState(0);
  const navigate = useNavigate();
  const maxRetries = 3;
  const [activeSection, setActiveSection] = useState('Welcome');
  const role = localStorage.getItem('role');

  useEffect(() => {
    const fetchWelcome = async () => {
      setIsLoading(true);
      setError(''); // Reset error on new fetch attempt
      try {
        const token = localStorage.getItem('access_token');
        if (!token) {
          setError('No authentication token found. Redirecting to login...');
          setTimeout(() => navigate('/'), 2000);
          return;
        }

        const response = await axios.get('http://localhost:5000/api/onboarding/welcome', {
          headers: { Authorization: `Bearer ${token}` },
        });
        console.log('Welcome API response:', response.data);
        setData(response.data);
      } catch (err) {
        console.error('Welcome API error:', err.response?.data);
        const status = err.response?.status;
        const message = err.response?.data?.message || 'Failed to load welcome content';

        if (status === 404) {
          setError('No welcome content available. Please contact HR.');
        } else if (status === 401 || status === 403) {
          setError('Session expired or unauthorized. Redirecting to login...');
          localStorage.removeItem('access_token');
          localStorage.removeItem('role');
          setTimeout(() => navigate('/'), 2000);
        } else if (retryCount < maxRetries) {
          setRetryCount(retryCount + 1);
          setTimeout(() => fetchWelcome(), 1000 * (retryCount + 1));
          return;
        } else {
          setError(`Failed to load content after ${maxRetries} attempts: ${message}`);
        }
      } finally {
        setIsLoading(false);
      }
    };

    fetchWelcome();
  }, [navigate, retryCount]);

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('role');
    navigate('/');
  };

  // Handle loading or error states
  if (isLoading || error) {
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
            <h1 className="content-title">Welcome, {data?.username || 'User'}</h1>
            <p className="content-subtitle">Role: {role?.toUpperCase() || 'EMPLOYEE'}</p>
          </div>
          <div className="section">
            <div className="card user-management">
              {isLoading ? (
                <p className="text-center">Loading welcome content...</p>
              ) : error ? (
                <p className="text-red-500 text-center">{error}</p>
              ) : null}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Convert YouTube watch URL to embed URL if necessary
  const embedVideoUrl = data.video_url?.includes('watch?v=')
    ? data.video_url.replace('watch?v=', 'embed/')
    : data.video_url;

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
          <h1 className="content-title">Welcome, {data?.username || 'User'}</h1>
          <p className="content-subtitle">Role: {role?.toUpperCase() || 'EMPLOYEE'}</p>
        </div>
        {error && <p className="error-message">{error}</p>}
        <div className="section">
          <div className="card user-management">
            <h2 className="card-title-large">Welcome to the Team!</h2>
            <p className="text-lg mb-6">{data.message}</p>
            {embedVideoUrl ? (
              <div className="video-wrapper">
                <iframe
                  src={embedVideoUrl}
                  frameBorder="0"
                  allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                  allowFullScreen
                  title="Welcome Video"
                ></iframe>
              </div>
            ) : (
              <p className="text-red-500 text-center">No video available</p>
            )}
            <div className="text-center">
              {data.zoom?.join_url ? (
                <a
                  href={data.zoom.join_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="action-btn bg-blue-500"
                >
                  Join Virtual Team Introduction
                </a>
              ) : (
                <p className="text-red-500">
                  Zoom meeting unavailable. Please contact HR for details.
                </p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Welcome;