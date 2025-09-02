import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import LoginPage from './LoginPage';
import RegisterPage from './RegisterPage';
import Welcome from './Welcome';
import UploadForm from './UploadForm';
import PolicyViewer from './PolicyViewer';
import SignatureForm from './SignatureForm';
import SponsorApproval from './SponsorApproval';
import Dashboard from './Dashboard';
import './App.css';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/welcome" element={<Welcome />} />
        <Route path="/upload" element={<UploadForm />} />
        <Route path="/policies" element={<PolicyViewer />} />
        <Route path="/signature/:envelopeId" element={<SignatureForm />} />
        <Route path="/sponsor_approve" element={<SponsorApproval />} />
      </Routes>
    </Router>
  );
}

export default App;