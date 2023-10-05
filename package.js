Package.describe({
  name: 'ndev:mfa',
  version: '0.1.2',
  summary: 'Multi Factor Authentication and Passwordless (supporting U2F, TOTP, and OTP)',
  git: 'https://github.com/TheRealNate/meteor-mfa',
  documentation: 'README.md'
});

Npm.depends({
  "@webauthn/server":"0.1.3",
  "@webauthn/client":"0.1.3",
  "otplib":"12.0.0"
});

Package.onUse(function(api) {
  api.versionsFrom(['1.8', '2.3']);
  api.use('ecmascript');
  api.use('accounts-base');
  api.use('random');
  api.use('check');
  api.mainModule('mfa-client.js', "client");
  api.mainModule('mfa-server.js', "server");
});
