// Account menu for the testing site: opens AuthNest's hosted account pages already signed in.
//
// Each item goes to the backend's /api/authnest/portal route (Testing Backend/authnestSession.js),
// which asks AuthNest for a one-time code and redirects. On the AuthNest page the user gets a
// "Back to <this site>" link that returns them to the page they left.
//
// Same behaviour as <UserButton /> in @elvoroz/authnest-react >= 1.2.0 — once that version is
// installed this file can be replaced by:  import { UserButton } from '@elvoroz/authnest-react';

import { useEffect, useRef, useState } from 'react';
import { useAuthNest } from '@elvoroz/authnest-react';

const PAGES = [
  { page: 'dashboard', label: 'Dashboard' },
  { page: 'profile', label: 'Profile' },
  { page: 'security', label: 'Security' },
  { page: 'devices', label: 'Devices & sessions' },
  { page: 'activity', label: 'Activity' },
  { page: 'notifications', label: 'Notifications' },
  { page: 'support', label: 'Help & support' },
];

const portalUrl = (page) =>
  `/api/authnest/portal?${new URLSearchParams({ page, return_to: window.location.href }).toString()}`;

const AccountMenu = () => {
  const { authStatus, handleLogout } = useAuthNest();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    const onDown = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey); };
  }, [open]);

  if (!authStatus.isAuthenticated) return null;

  return (
    <div className="account-menu" ref={ref}>
      <button type="button" className="account-menu-chip" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        <span className="account-menu-avatar" aria-hidden="true">A</span>
        <span>My account</span>
      </button>
      {open && (
        <div className="account-menu-list" role="menu">
          {PAGES.map((p) => (
            <a key={p.page} role="menuitem" className="account-menu-item" href={portalUrl(p.page)}>{p.label}</a>
          ))}
          <button type="button" role="menuitem" className="account-menu-item account-menu-signout" onClick={() => { setOpen(false); handleLogout(); }}>
            Log out
          </button>
        </div>
      )}
    </div>
  );
};

export default AccountMenu;
