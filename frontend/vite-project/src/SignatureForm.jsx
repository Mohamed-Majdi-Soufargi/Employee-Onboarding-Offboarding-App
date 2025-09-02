import { useState, useEffect } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';

function SignatureForm() {
  const [signingUrl, setSigningUrl] = useState('');
  const [error, setError] = useState('');
  const { envelopeId } = useParams();
  const navigate = useNavigate();

  useEffect(() => {
    const fetchSigningUrl = async () => {
      try {
        const token = localStorage.getItem('access_token');
        if (!token) {
          setError('No authentication token found');
          navigate('/');
          return;
        }
        const response = await axios.post(
          '/api/get_signing_url',
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
    fetchSigningUrl();
  }, [envelopeId, navigate]);

  return (
    <div className="min-h-screen bg-gray-100 p-4">
      <div className="max-w-4xl mx-auto">
        <h2 className="text-3xl font-bold mb-6 text-center">Sign Policy</h2>
        {error ? (
          <p className="text-red-500 text-center">{error}</p>
        ) : !signingUrl ? (
          <p className="text-center text-gray-700">Loading signing form...</p>
        ) : (
          <iframe
            src={signingUrl}
            title="DocuSign Signing"
            className="w-full h-[800px] border rounded-md"
          />
        )}
      </div>
    </div>
  );
}

export default SignatureForm;