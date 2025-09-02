import { useState, useEffect } from 'react';
import axios from 'axios';
import { useLocation, useNavigate } from 'react-router-dom';

function SponsorApproval() {
  const [token, setToken] = useState('');
  const [user, setUser] = useState(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    const query = new URLSearchParams(location.search);
    const approvalToken = query.get('token');
    if (approvalToken) {
      setToken(approvalToken);
      fetchUser(approvalToken);
    } else {
      setError('No approval token provided');
      setTimeout(() => navigate('/'), 3000);
    }
  }, [location, navigate]);

  const fetchUser = async (approvalToken) => {
    try {
      const response = await axios.get(`/api/sponsor_approve?token=${approvalToken}`);
      setUser(response.data);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load user details');
      setTimeout(() => navigate('/'), 3000);
    }
  };

  const handleApproval = async (approve) => {
    try {
      await axios.post('/api/sponsor_approve', { token, approve });
      setSuccess(`User ${approve ? 'approved' : 'rejected'} successfully`);
      setError('');
      setTimeout(() => navigate('/'), 3000);
    } catch (err) {
      setError(err.response?.data?.message || `Failed to ${approve ? 'approve' : 'reject'} user`);
    }
  };

  return (
    <div className="min-h-screen bg-gray-100 p-4">
      <div className="max-w-md mx-auto bg-white p-8 rounded-lg shadow-md">
        <h2 className="text-2xl font-bold mb-6 text-center">Sponsor Approval</h2>
        {error ? (
          <p className="text-red-500 text-center">{error}</p>
        ) : !user ? (
          <p className="text-center text-gray-700">Loading...</p>
        ) : (
          <>
            <p className="mb-4 text-center">
              Approve or reject registration for <strong>{user.username}</strong>
            </p>
            <div className="flex justify-center gap-4">
              <button
                onClick={() => handleApproval(true)}
                className="bg-green-500 text-white px-4 py-2 rounded-md hover:bg-green-600"
              >
                Approve
              </button>
              <button
                onClick={() => handleApproval(false)}
                className="bg-red-500 text-white px-4 py-2 rounded-md hover:bg-red-600"
              >
                Reject
              </button>
            </div>
            {success && <p className="mt-4 text-green-500 text-center">{success}</p>}
          </>
        )}
      </div>
    </div>
  );
}

export default SponsorApproval;