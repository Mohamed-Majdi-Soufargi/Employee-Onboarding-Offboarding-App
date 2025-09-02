import { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Dashboard() {
  const [userData, setUserData] = useState(null);
  const [hrUsers, setHrUsers] = useState([]);
  const [pendingApprovals, setPendingApprovals] = useState([]);
  const [error, setError] = useState('');
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
        const protectedResponse = await axios.get('/api/protected', {
          headers: { Authorization: `Bearer ${token}` },
        });
        setUserData(protectedResponse.data);

        if (role === 'hr') {
          const hrResponse = await axios.get('/api/hr/users', {
            headers: { Authorization: `Bearer ${token}` },
          });
          setHrUsers(hrResponse.data);

          const approvalsResponse = await axios.get('/api/pending_approvals', {
            headers: { Authorization: `Bearer ${token}` },
          });
          setPendingApprovals(approvalsResponse.data.pending_approvals || []);
        }
      } catch (err) {
        setError(err.response?.data?.message || 'Failed to fetch data');
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
        `/api/hr/users/${userId}/deactivate`,
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
        '/api/sponsor_approve',
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

  return (
    <div className="min-h-screen bg-gray-100 p-4">
      <div className="max-w-4xl mx-auto">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <button
            onClick={handleLogout}
            className="bg-red-500 text-white px-4 py-2 rounded-md hover:bg-red-600"
          >
            Logout
          </button>
        </div>

        {error && <p className="text-red-500 mb-4 text-center">{error}</p>}

        {userData && (
          <div className="bg-white p-6 rounded-lg shadow-md mb-6">
            <h2 className="text-xl font-semibold mb-4">Welcome, {userData.username}</h2>
            <p className="text-gray-700">Role: {role}</p>
          </div>
        )}

        {role === 'employee' && (
          <div className="bg-white p-6 rounded-lg shadow-md mb-6">
            <h2 className="text-xl font-semibold mb-4">Employee Dashboard</h2>
            <p className="mb-4">Complete your onboarding process below:</p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <button
                onClick={() => navigate('/welcome')}
                className="bg-blue-500 text-white p-4 rounded-md hover:bg-blue-600"
              >
                View Welcome Content
              </button>
              <button
                onClick={() => navigate('/upload')}
                className="bg-green-500 text-white p-4 rounded-md hover:bg-green-600"
              >
                Upload Documents
              </button>
              <button
                onClick={() => navigate('/policies')}
                className="bg-purple-500 text-white p-4 rounded-md hover:bg-purple-600"
              >
                Review & Sign Policies
              </button>
            </div>
          </div>
        )}

        {role === 'hr' && (
          <>
            <div className="bg-white p-6 rounded-lg shadow-md mb-6">
              <h2 className="text-xl font-semibold mb-4">Pending Sponsor Approvals</h2>
              {pendingApprovals.length === 0 ? (
                <p className="text-gray-700">No pending approvals.</p>
              ) : (
                <table className="w-full border-collapse">
                  <thead>
                    <tr className="bg-gray-200">
                      <th className="border p-2">ID</th>
                      <th className="border p-2">Username</th>
                      <th className="border p-2">Email</th>
                      <th className="border p-2">Role</th>
                      <th className="border p-2">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pendingApprovals.map((approval) => (
                      <tr key={approval.id}>
                        <td className="border p-2">{approval.id}</td>
                        <td className="border p-2">{approval.username}</td>
                        <td className="border p-2">{approval.email}</td>
                        <td className="border p-2">{approval.role}</td>
                        <td className="border p-2 flex space-x-2">
                          <button
                            onClick={() => handleApprovalAction(approval.approval_token, true)}
                            className="bg-green-500 text-white px-2 py-1 rounded-md hover:bg-green-600"
                          >
                            Approve
                          </button>
                          <button
                            onClick={() => handleApprovalAction(approval.approval_token, false)}
                            className="bg-red-500 text-white px-2 py-1 rounded-md hover:bg-red-600"
                          >
                            Reject
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {hrUsers.length > 0 && (
              <div className="bg-white p-6 rounded-lg shadow-md">
                <h2 className="text-xl font-semibold mb-4">User Management</h2>
                <table className="w-full border-collapse">
                  <thead>
                    <tr className="bg-gray-200">
                      <th className="border p-2">ID</th>
                      <th className="border p-2">Username</th>
                      <th className="border p-2">Email</th>
                      <th className="border p-2">Role</th>
                      <th className="border p-2">Active</th>
                      <th className="border p-2">Sponsor Email</th>
                      <th className="border p-2">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hrUsers.map((user) => (
                      <tr key={user.id}>
                        <td className="border p-2">{user.id}</td>
                        <td className="border p-2">{user.username}</td>
                        <td className="border p-2">{user.email}</td>
                        <td className="border p-2">{user.role}</td>
                        <td className="border p-2">{user.is_active ? 'Yes' : 'No'}</td>
                        <td className="border p-2">{user.sponsor_email}</td>
                        <td className="border p-2">
                          {user.is_active && (
                            <button
                              onClick={() => handleDeactivate(user.id)}
                              className="bg-red-500 text-white px-2 py-1 rounded-md hover:bg-red-600"
                            >
                              Deactivate
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default Dashboard;