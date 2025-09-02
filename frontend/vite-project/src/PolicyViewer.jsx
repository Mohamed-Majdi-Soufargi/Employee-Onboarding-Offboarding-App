import { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function UploadForm() {
  const [file, setFile] = useState(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const navigate = useNavigate();

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
      await axios.post('/api/upload', formData, {
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

  return (
    <div
      className="min-h-screen bg-gray-100 p-4"
      onDrop={handleDrop}
      onDragOver={(e) => e.preventDefault()}
    >
      <div className="max-w-md mx-auto bg-white p-8 rounded-lg shadow-md">
        <h2 className="text-2xl font-bold mb-6 text-center">Upload Secure Document</h2>
        <form onSubmit={handleSubmit}>
          <input
            type="file"
            accept=".pdf,.png"
            onChange={handleChange}
            className="w-full p-2 mb-4 border rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <button
            type="submit"
            className="w-full bg-green-500 text-white p-2 rounded-md hover:bg-green-600"
          >
            Upload
          </button>
        </form>
        {error && <p className="mt-4 text-red-500 text-center">{error}</p>}
        {success && <p className="mt-4 text-green-500 text-center">{success}</p>}
        <p className="mt-4 text-gray-500 text-center">Drag and drop PDF or PNG files here</p>
      </div>
    </div>
  );
}

export default UploadForm;