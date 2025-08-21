import { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Dashboard() {
  const [userData, setUserData] = useState(null);
  const [hrUsers, setHrUsers] = useState([]);
  const [itConfig, setItConfig] = useState(null);
  const [error, setError] = useState('');
  const role = localStorage.getItem('role');
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        navigate('/');
        return;
      }

      try {
        const protectedResponse = await axios.get('/api/protected', {
          headers: { Authorization: `Bearer ${token}` }
        });
        setUserData(protectedResponse.data);

        if (role === 'hr') {
          const hrResponse = await axios.get('/api/hr/users', {
            headers: { Authorization: `Bearer ${token}` }
          });
          setHrUsers(hrResponse.data);
        } else if (role === 'it') {
          const itResponse = await axios.get('/api/it/config', {
            headers: { Authorization: `Bearer ${token}` }
          });
          setItConfig(itResponse.data.config);
        }
      } catch (err) {
        setError(err.response?.data?.message || 'Failed to fetch data');
        if (err.response?.status === 401 || err.response?.status === 403) {
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
      await axios.post(`/api/hr/users/${userId}/deactivate`, {}, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      setHrUsers(hrUsers.map(user => 
        user.id === userId ? { ...user, is_active: false } : user
      ));
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to deactivate user');
    }
  };

  const handleLogout = () => {
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

      {role === 'it' && itConfig && (
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">System Configuration</h2>
          <p><strong>System Version:</strong> {itConfig.system_version}</p>
          <p><strong>MFA Enabled:</strong> {itConfig.mfa_enabled ? 'Yes' : 'No'}</p>
          <p><strong>Max Login Attempts:</strong> {itConfig.max_login_attempts}</p>
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