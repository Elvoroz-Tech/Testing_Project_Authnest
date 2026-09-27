import { useEffect, useRef } from 'react';
import { useAuthNest } from '@elvoroz/authnest-react';
import { getLocalSession, needsRenewal, nextCheckDelayMs, renewSession, fetchServerSession } from '../utils/sessionRenewal';

// Renders nothing. Mount once, inside <AuthNestProvider>, and the signed-in visitor stays signed in.
//
// The newer AuthNest gives a 1-hour access token + a rotating 30-day refresh token. @elvoroz/authnest-react
// stores both in cookies but doesn't renew them on its own, so this component:
//   • renews shortly BEFORE the access token expires (and immediately if it already has — e.g. after
//     a page load an hour later, or a laptop waking from sleep);
//   • re-checks when the tab becomes visible again or the network returns;
//   • tells @elvoroz/authnest-react to re-read its status after a renewal or a sign-out, so the navbar and
//     buttons reflect reality without a page reload.
// The renewal itself is done by this app's backend (see utils/sessionRenewal.js).
const SessionKeeper = () => {
  const { authStatus, retryAuthCheck } = useAuthNest();

  // The check loop is set up once; it reads the latest SDK state through refs.
  const statusRef = useRef(authStatus);
  const retryRef = useRef(retryAuthCheck);
  useEffect(() => { statusRef.current = authStatus; retryRef.current = retryAuthCheck; });

  useEffect(() => {
    let timer = null;
    let stopped = false;

    const check = async () => {
      let session = getLocalSession();

      // A session that only exists as httpOnly cookies is invisible to JavaScript — ask the backend
      // (one cheap request, no AuthNest call) so it can still be kept alive.
      if (!session.hasAccess && !session.hasRefresh) {
        const server = await fetchServerSession();
        if (server && server.renewable) {
          session = { hasAccess: !!server.hasAccessToken, hasRefresh: true, accessExpiresInMs: server.accessExpiresInSeconds == null ? null : server.accessExpiresInSeconds * 1000 };
        }
      }

      if (needsRenewal(session)) {
        const result = await renewSession();
        if (!stopped && (result.status === 'renewed' || result.status === 'signed_out')) {
          // Let the SDK re-read the cookies only when its view is out of date.
          const sdkSaysSignedIn = statusRef.current.isAuthenticated;
          const reality = result.status === 'renewed';
          if (sdkSaysSignedIn !== reality) retryRef.current();
        }
        session = getLocalSession();
      }

      if (!stopped) timer = setTimeout(check, nextCheckDelayMs(session));
    };

    const wake = () => { clearTimeout(timer); check(); };
    const onVisible = () => { if (document.visibilityState === 'visible') wake(); };
    document.addEventListener('visibilitychange', onVisible);
    window.addEventListener('online', wake);
    window.addEventListener('authnest-testing:check-session', wake); // used by the Session testing page
    check();

    return () => {
      stopped = true;
      clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisible);
      window.removeEventListener('online', wake);
      window.removeEventListener('authnest-testing:check-session', wake);
    };
  }, []);

  return null;
};

export default SessionKeeper;
