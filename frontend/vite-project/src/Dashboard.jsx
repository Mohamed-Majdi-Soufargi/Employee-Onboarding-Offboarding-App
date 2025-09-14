import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import './Dashboard.css';

function Dashboard() {
  const [activeSection, setActiveSection] = useState('Users');
  const [userData, setUserData] = useState(null);
  const [hrUsers, setHrUsers] = useState([]);
  const [pendingApprovals, setPendingApprovals] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [showNotifications, setShowNotifications] = useState(false);
  const [error, setError] = useState('');
  const [logCount, setLogCount] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const logsPerPage = 10;
  const role = localStorage.getItem('role');
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      const token = localStorage.getItem('access_token');
      if (!token) {
        setError('No authentication token found');
        navigate('/');
        return;
      }

      try {
        const protectedResponse = await axios.get('http://localhost:5000/api/protected', {
          headers: { Authorization: `Bearer ${token}` },
        });
        setUserData(protectedResponse.data);

        if (role === 'hr') {
          const hrResponse = await axios.get('http://localhost:5000/api/hr/users', {
            headers: { Authorization: `Bearer ${token}` },
          });
          setHrUsers(hrResponse.data || []);

          const approvalsResponse = await axios.get('http://localhost:5000/api/pending_approvals', {
            headers: { Authorization: `Bearer ${token}` },
          });
          setPendingApprovals(approvalsResponse.data.pending_approvals || []);

          const auditResponse = await axios.get('http://localhost:5000/api/audit_logs', {
            headers: { Authorization: `Bearer ${token}` },
          });
          // Ensure logs are sorted by timestamp in descending order
          const sortedLogs = auditResponse.data.sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
          );
          setAuditLogs(sortedLogs || []);

          const countResponse = await axios.get('http://localhost:5000/api/check_logs', {
            headers: { Authorization: `Bearer ${token}` },
          });
          setLogCount(countResponse.data.log_count);
        }
      } catch (err) {
        setError(
          err.response?.data?.message ||
          'Failed to fetch data. Ensure the Flask server is running at http://localhost:5000.'
        );
        console.error('Fetch error:', err);
        if (err.response?.status === 401 || err.response?.status === 403) {
          localStorage.removeItem('access_token');
          localStorage.removeItem('role');
          navigate('/');
        }
      }
    };

    fetchData();
  }, [role, navigate]);

  const handleDeactivate = async (userId) => {
    try {
      await axios.post(
        `http://localhost:5000/api/hr/users/${userId}/deactivate`,
        {},
        {
          headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` },
        }
      );
      setHrUsers(
        hrUsers.map((user) =>
          user.id === userId ? { ...user, is_active: false } : user
        )
      );
      setError('User deactivated successfully');
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to deactivate user');
    }
  };

  const handleApprovalAction = async (approvalToken, approve) => {
    try {
      const response = await axios.post(
        'http://localhost:5000/api/sponsor_approve',
        { token: approvalToken, approve },
        { headers: { Authorization: `Bearer ${localStorage.getItem('access_token')}` } }
      );
      setPendingApprovals(
        pendingApprovals.filter((approval) => approval.approval_token !== approvalToken)
      );
      setError(response.data.message);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to process approval');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('role');
    navigate('/');
  };

  const fetchNotifications = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await axios.get('http://localhost:5000/api/notifications', {
        headers: { Authorization: `Bearer ${token}` },
      });
      setNotifications(response.data || []);
      setShowNotifications(true);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to fetch notifications');
    }
  };

  // Pagination logic
  const indexOfLastLog = currentPage * logsPerPage;
  const indexOfFirstLog = indexOfLastLog - logsPerPage;
  const currentLogs = auditLogs.slice(indexOfFirstLog, indexOfLastLog);
  const totalPages = Math.ceil(auditLogs.length / logsPerPage);

  const handlePreviousPage = () => {
    if (currentPage > 1) {
      setCurrentPage(currentPage - 1);
    }
  };

  const handleNextPage = () => {
    if (currentPage < totalPages) {
      setCurrentPage(currentPage + 1);
    }
  };

  return (
    <div className="dashboard-container">
      <div className="sidebar">
        <h2 className="sidebar-header">Dashboard</h2>
        <div
          className={`nav-item ${activeSection === 'Users' ? 'active' : ''}`}
          onClick={() => setActiveSection('Users')}
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
          onClick={() => setActiveSection('Tasks')}
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
          onClick={() => setActiveSection('Settings')}
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
        <div className="header-actions">
          <button
            className="notification-btn"
            onClick={fetchNotifications}
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
            >
              <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
              <path d="M13.73 21a2 2 0 0 1-3.46 0" />
            </svg>
            {notifications.length > 0 && <span className="notification-count">{notifications.length}</span>}
          </button>
          {showNotifications && (
            <div className="notification-dropdown">
              {notifications.length > 0 ? (
                <ul className="notification-list">
                  {notifications.map((notif, index) => (
                    <li key={index} className="notification-item">{notif.message}</li>
                  ))}
                </ul>
              ) : (
                <p className="notification-empty">No new notifications.</p>
              )}
            </div>
          )}
        </div>
        <div className="content-header">
          <h1 className="content-title">Welcome, {userData?.username || 'User'}</h1>
          <p className="content-subtitle">Role: {role?.toUpperCase() || 'EMPLOYEE'}</p>
        </div>
        {error && <p className="error-message">{error}</p>}
        {logCount !== null && <p>Log Count: {logCount}</p>}
        {role === 'employee' && activeSection === 'Users' && (
          <div className="content-layout">
            <div className="welcome-section">
              <p className="welcome-text">
                Welcome to our team! We're excited to have you on board. To get started, please complete the onboarding process below. This will help you familiarize yourself with the company, upload necessary documents, and review our policies. If you have any questions, feel free to reach out to your HR representative.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <button
                  onClick={() => navigate('/welcome')}
                  className="action-btn bg-blue-500"
                >
                  View Welcome Content
                </button>
                <button
                  onClick={() => navigate('/upload')}
                  className="action-btn bg-green-500"
                >
                  Upload Documents
                </button>
                <button
                  onClick={() => navigate('/policies')}
                  className="action-btn bg-purple-500"
                >
                  Review & Sign Policies
                </button>
              </div>
            </div>
            <div className="calendar-section">
              <h3 className="calendar-title">Calendar</h3>
              <div className="calendar-grid">
                <div className="calendar-header">
                  <span>Sun</span>
                  <span>Mon</span>
                  <span>Tue</span>
                  <span>Wed</span>
                  <span>Thu</span>
                  <span>Fri</span>
                  <span>Sat</span>
                </div>
                <div className="calendar-days">
                  {Array(42)
                    .fill(null)
                    .map((_, i) => (
                      <div key={i} className="calendar-day"></div>
                    ))}
                </div>
              </div>
            </div>
          </div>
        )}
        <div className="main-content">
          {activeSection === 'Users' && role === 'hr' && (
            <div className="section">
              {hrUsers.length > 0 && (
                <div className="content-layout">
                  <div className="card user-management">
                    <h2 className="card-title-large">User Management</h2>
                    <div className="table-wrapper">
                      <table className="management-table">
                        <thead>
                          <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Active</th>
                            <th>Sponsor Email</th>
                            <th>Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {hrUsers.map((user) => (
                            <tr key={user.id}>
                              <td>{user.id}</td>
                              <td>{user.username}</td>
                              <td>{user.email}</td>
                              <td>{user.role.toUpperCase()}</td>
                              <td>{user.is_active ? 'Yes' : 'No'}</td>
                              <td>{user.sponsor_email}</td>
                              <td>
                                {user.is_active && (
                                  <button
                                    onClick={() => handleDeactivate(user.id)}
                                    className="deactivate-btn"
                                  >
                                    Deactivate
                                  </button>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      <h3 className="card-title-large">Audit Logs</h3>
                      <table className="management-table">
                        <thead>
                          <tr>
                            <th>ID</th>
                            <th>Type</th>
                            <th>Success</th>
                            <th>Reason</th>
                            <th>Username</th>
                            <th>Timestamp</th>
                          </tr>
                        </thead>
                        <tbody>
                          {currentLogs.length > 0 ? (
                            currentLogs.map((log) => (
                              <tr key={log.id}>
                                <td>{log.id}</td>
                                <td>{log.type}</td>
                                <td>{log.success ? 'Yes' : 'No'}</td>
                                <td>{log.reason}</td>
                                <td>{log.username || 'N/A'}</td>
                                <td>{new Date(log.timestamp).toLocaleString()}</td>
                              </tr>
                            ))
                          ) : (
                            <tr>
                              <td colSpan="6">No audit logs available.</td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                      <div className="pagination">
                        <button
                          className="pagination-btn"
                          onClick={handlePreviousPage}
                          disabled={currentPage === 1}
                        >
                          Previous
                        </button>
                        <span>Page {currentPage} of {totalPages || 1}</span>
                        <button
                          className="pagination-btn"
                          onClick={handleNextPage}
                          disabled={currentPage === totalPages}
                        >
                          Next
                        </button>
                      </div>
                    </div>
                  </div>
                  <div className="calendar-section">
                    <h3 className="calendar-title">Calendar</h3>
                    <div className="calendar-grid">
                      <div className="calendar-header">
                        <span>Sun</span>
                        <span>Mon</span>
                        <span>Tue</span>
                        <span>Wed</span>
                        <span>Thu</span>
                        <span>Fri</span>
                        <span>Sat</span>
                      </div>
                      <div className="calendar-days">
                        {Array(42)
                          .fill(null)
                          .map((_, i) => (
                            <div key={i} className="calendar-day"></div>
                          ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
          {activeSection === 'Tasks' && (
            <div className="section">
              {role === 'hr' && (
                <div className="card user-management">
                  <h2 className="card-title-large">Pending Sponsor Approvals</h2>
                  <div className="table-wrapper">
                    <table className="management-table">
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Username</th>
                          <th>Email</th>
                          <th>Role</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {pendingApprovals.length > 0 ? (
                          pendingApprovals.map((approval) => (
                            <tr key={approval.id}>
                              <td>{approval.id}</td>
                              <td>{approval.username}</td>
                              <td>{approval.email}</td>
                              <td>{approval.role}</td>
                              <td>
                                <button
                                  onClick={() => handleApprovalAction(approval.approval_token, true)}
                                  className="approve-btn"
                                >
                                  Approve
                                </button>
                                <button
                                  onClick={() => handleApprovalAction(approval.approval_token, false)}
                                  className="reject-btn"
                                >
                                  Reject
                                </button>
                              </td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td colSpan="5">No pending approvals.</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
              {role === 'employee' && (
                <div className="card user-management">
                  <h2 className="card-title-large">Tasks</h2>
                  <div className="task-list">
                    <ul>
                      <li>View Welcome Content</li>
                      <li>Upload Necessary Documents</li>
                      <li>Review & Sign Policies</li>
                    </ul>
                  </div>
                </div>
              )}
            </div>
          )}
          {activeSection === 'Settings' && (
            <div className="section">
              <div className="card-grid">
                <div className="card">
                  <h3 className="card-title">Coming Soon</h3>
                  <p className="card-value"></p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default Dashboard;