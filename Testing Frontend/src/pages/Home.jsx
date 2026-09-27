import { UserProfileButton, GetUserDataButton, SecuritySettingsButton } from '@elvoroz/authnest-react';
import { useState } from 'react';

const HomePage = () => {
  const [userData, setUserData] = useState(null);
  return (
    <div className="dashboard">
      <GetUserDataButton onData={setUserData} className="card-btn" />
      <UserProfileButton className="card-btn" />
      <SecuritySettingsButton className="card-btn" />
      {userData && <p>Welcome, {userData.name}</p>}
    </div>
  );
};
export default HomePage