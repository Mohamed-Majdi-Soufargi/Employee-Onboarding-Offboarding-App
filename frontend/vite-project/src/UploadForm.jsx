import { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './UploadForm.css';

function UploadForm() {
  const [file, setFile] = useState(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();
  const [activeSection, setActiveSection] = useState('Upload');
  const role = localStorage.getItem('role');

  const handleChange = (e) => {
    setFile(e.target.files[0]);
    setError('');
    setSuccess('');
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setFile(e.dataTransfer.files[0]);
    setError('');
    setSuccess('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const token = localStorage.getItem('access_token');
    if (!token) {
      setError('No authentication token found');
      navigate('/');
      return;
    }
    if (!file) {
      setError('Please select a file');
      return;
    }
    if (!file.name.match(/\.(pdf|png)$/i)) {
      setError('Only PDF and PNG files are allowed');
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setError('File must be less than 10MB');
      return;
    }
    const formData = new FormData();
    formData.append('file', file);
    try {
      await axios.post('http://localhost:5000/api/upload', formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data',
        },
      });
      setSuccess('File uploaded successfully');
      setFile(null);
      setError('');
    } catch (err) {
      setError(err.response?.data?.message || 'File upload failed');
      if (err.response?.status === 401 || err.response?.status === 403) {
        localStorage.removeItem('access_token');
        localStorage.removeItem('role');
        navigate('/');
      }
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('role');
    navigate('/');
  };

  return (
    <div
      className="dashboard-container"
      onDrop={handleDrop}
      onDragOver={(e) => e.preventDefault()}
    >
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
          <h1 className="content-title">Upload Documents</h1>
          <p className="content-subtitle">Role: {role?.toUpperCase() || 'EMPLOYEE'}</p>
        </div>
        {error && <p className="error-message">{error}</p>}
        {success && <p className="success-message">{success}</p>}
        <div className="section">
          <div className="card user-management">
            <h2 className="card-title-large">Upload Secure Document</h2>
            <p className="text-lg mb-6">
              Please upload the required onboarding document.
              Only PDF and PNG files are accepted, with a maximum file size of 10MB.
              You can select a file by clicking below or drag and drop it into this area.
            </p>
            <form onSubmit={handleSubmit}>
              <input
                type="file"
                accept=".pdf,.png"
                onChange={handleChange}
                className="w-full p-2 mb-4 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <button
                type="submit"
                className="action-btn bg-green-500 w-full"
              >
                Upload
              </button>
            </form>
            <p className="text-gray-500 text-center mt-4">Drag and drop PDF or PNG files here</p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default UploadForm;