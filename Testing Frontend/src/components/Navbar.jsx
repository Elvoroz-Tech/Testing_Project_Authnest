import { LoginButton, RegisterButton } from '@elvoroz/authnest-react';
import { useAuthNest } from '@elvoroz/authnest-react';
import { Link } from 'react-router-dom';
import AccountMenu from './AccountMenu';

const Navbar = () => {
  const { authStatus } = useAuthNest();
  return (
    <nav className="navbar">
      <span className="logo">Testing Navbar</span>
      <Link className="nav-link" to="/">Home</Link>
      <Link className="nav-link" to="/ModalsTesting">Modals</Link>
      <Link className="nav-link" to="/SessionTesting">Session</Link>
      {authStatus.isAuthenticated ? (
        <AccountMenu />
      ) : (
        <>
          <LoginButton as="a" className="nav-link" />
          <RegisterButton className="btn-primary" />
        </>
      )}
    </nav>
  );
};

export default Navbar
