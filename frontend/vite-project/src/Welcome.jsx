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

        const response = await axios.get('/api/onboarding/welcome', {
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

  // Prevent re-render if data is already set and valid
  if (data && !isLoading && !error) {
    // Convert YouTube watch URL to embed URL if necessary
    const embedVideoUrl = data.video_url?.includes('watch?v=')
      ? data.video_url.replace('watch?v=', 'embed/')
      : data.video_url;

    return (
      <div className="min-h-screen bg-gray-100 p-4">
        <div className="max-w-4xl mx-auto bg-white p-8 rounded-lg shadow-md">
          <h2 className="text-3xl font-bold mb-6 text-center">Welcome to the Team!</h2>
          <p className="text-lg mb-6 text-center">{data.message}</p>
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
                className="inline-block bg-blue-500 text-white px-6 py-3 rounded-md hover:bg-blue-600"
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
    );
  }

  // Handle loading or error states
  return (
    <div className="min-h-screen bg-gray-100 p-4 flex items-center justify-center">
      <div className="bg-white p-8 rounded-lg shadow-md">
        {isLoading ? (
          <p className="text-center">Loading welcome content...</p>
        ) : error ? (
          <p className="text-red-500 text-center">{error}</p>
        ) : null}
      </div>
    </div>
  );
}

export default Welcome;