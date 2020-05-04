Package.describe({
  name: 'ndev:mfa',
  version: '0.0.1',
  summary: 'Multi Factor Authentication for Meteor (with U2F support)',
  git: 'https://github.com/TheRealNate/meteor-mfa',
  documentation: 'README.md'
});

Npm.depends({
  "@webauthn/server":"0.1.3",
  "@webauthn/client":"0.1.3"
});

Package.onUse(function(api) {
  api.versionsFrom('1.8');
  api.use('ecmascript');
  api.use('accounts-base');
  api.mainModule('mfa-client.js', "client");
  api.mainModule('mfa-server.js', "server");
});
