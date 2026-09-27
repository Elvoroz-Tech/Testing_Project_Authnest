import { TwoFactorModalButton, PasswordConfirmModalButton, EmailVerificationModalButton } from '@elvoroz/authnest-react';

const ModalsTesting = () => {
  return (
    <div>
      <h1>AuthNest Modals Testing</h1>
      <TwoFactorModalButton
        onSuccess={(result) => console.log('2FA passed', result)}
        onError={(err) => console.error('2FA failed', err)}
      />
      <PasswordConfirmModalButton onSuccess={(r) => console.log('Password confirmed', r)} />
      <EmailVerificationModalButton onSuccess={(r) => console.log('Email verified', r)} />
    </div>
  );
};

export default ModalsTesting;