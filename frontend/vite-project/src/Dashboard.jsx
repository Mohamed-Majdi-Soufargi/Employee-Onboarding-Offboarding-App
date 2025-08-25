import { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

// Set the base URL for Axios to point to the Flask backend
axios.defaults.baseURL = 'http://localhost:5000';

function Dashboard() {
  const [userData, setUserData] = useState(null);
  const [hrUsers, setHrUsers] = useState([]);
  const [pendingApprovals, setPendingApprovals] = useState([]);
  const [error, setError] = useState('');
  const role = localStorage.getItem('role');
  const navigate = useNavigate();

  useEffect(() => {
    console.log('Role from localStorage:', role);
    console.log('Token from localStorage:', localStorage.getItem('token'));

    const fetchData = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        console.log('No token found, redirecting to login');
        navigate('/');
        return;
      }

      try {
        console.log('Fetching /api/protected with token:', token);
        const protectedResponse = await axios.get('/api/protected', {
          headers: { Authorization: `Bearer ${token}` }
        });
        setUserData(protectedResponse.data);
        console.log('Protected response:', protectedResponse.data);

        if (role === 'hr') {
          console.log('Fetching /api/hr/users');
          const hrResponse = await axios.get('/api/hr/users', {
            headers: { Authorization: `Bearer ${token}` }
          });
          setHrUsers(hrResponse.data);
          console.log('HR users response:', hrResponse.data);

          console.log('Fetching /api/pending_approvals');
          const approvalsResponse = await axios.get('/api/pending_approvals', {
            headers: { Authorization: `Bearer ${token}` }
          });
          setPendingApprovals(approvalsResponse.data.pending_approvals || []);
          console.log('Pending approvals response:', approvalsResponse.data);
          console.log('Pending approvals state:', approvalsResponse.data.pending_approvals || []);
        }
      } catch (err) {
        setError(err.response?.data?.message || 'Failed to fetch data');
        console.error('Error details:', {
          status: err.response?.status,
          data: err.response?.data,
          message: err.message
        });
        if (err.response?.status === 401 || err.response?.status === 403) {
          console.log('Unauthorized or Forbidden, clearing localStorage and redirecting');
          localStorage.removeItem('token');
          localStorage.removeItem('role');
          navigate('/');
        }
      }
    };

    fetchData();
  }, [role, navigate]);

  const handleDeactivate = async (userId) => {
    try {
      console.log('Deactivating user:', userId);
      await axios.post(`/api/hr/users/${userId}/deactivate`, {}, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      setHrUsers(hrUsers.map(user => 
        user.id === userId ? { ...user, is_active: false } : user
      ));
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to deactivate user');
      console.error('Deactivation error:', err);
    }
  };

  const handleApprovalAction = async (approvalToken, approve) => {
    try {
      console.log('Processing approval, token:', approvalToken, 'approve:', approve);
      const response = await axios.post('/api/sponsor_approve', 
        { token: approvalToken, approve },
        { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } }
      );
      setPendingApprovals(pendingApprovals.filter(approval => approval.approval_token !== approvalToken));
      setError(response.data.message);
      console.log('Approval response:', response.data);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to process approval');
      console.error('Approval error:', err);
    }
  };

  const handleLogout = () => {
    console.log('Logging out');
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    navigate('/');
  };

  return (
    <div className="container mx-auto p-4">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <button
          onClick={handleLogout}
          className="bg-red-500 text-white px-4 py-2 rounded-md hover:bg-red-600"
        >
          Logout
        </button>
      </div>

      {error && <p className="text-red-500 mb-4">{error}</p>}

      {userData && (
        <div className="bg-white p-6 rounded-lg shadow-md mb-6">
          <h2 className="text-xl font-semibold mb-4">{userData.message}</h2>
          <p>Role: {role}</p>
        </div>
      )}

      {role === 'hr' && (
        <div className="bg-white p-6 rounded-lg shadow-md mb-6">
          <h2 className="text-xl font-semibold mb-4">Pending Sponsor Approvals</h2>
          {pendingApprovals.length === 0 ? (
            <p>No pending approvals.</p>
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
      )}

      {role === 'hr' && hrUsers.length > 0 && (
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

      {role === 'employee' && (
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">Employee Dashboard</h2>
          <p>Welcome to your employee dashboard. Here you can view your profile and onboarding status.</p>
        </div>
      )}
    </div>
  );
}

export default Dashboard;