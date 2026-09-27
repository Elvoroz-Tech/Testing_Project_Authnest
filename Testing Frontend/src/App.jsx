import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Home from "./pages/Home";
import Navbar from "./components/Navbar";
import ModalsTesting from "./pages/ModalsTesting";
import SessionTesting from "./pages/SessionTesting";
import SessionKeeper from "./components/SessionKeeper";
import './App.css';
import { AuthNestProvider, AuthStatusPanel } from '@elvoroz/authnest-react';

function App() {
  return (
    <AuthNestProvider options={{ debug: import.meta.env.MODE === 'development' }}>
      <div className="App">

        <AuthStatusPanel />
      </div>
      {/* Keeps the 1-hour access token renewed so visitors aren't signed out hourly. */}
      <SessionKeeper />
      <Router>
        <Navbar/>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/ModalsTesting" element={<ModalsTesting />} />
          <Route path="/SessionTesting" element={<SessionTesting />} />
        </Routes>
      </Router>
    </AuthNestProvider>
  );
}

export default App;