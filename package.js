Package.describe({
  name: 'pablor21:accounts-password-phone',
  version: '0.0.1',
  // Brief, one-line summary of the package.
  summary: 'Accounts password with phone number',
  // URL to the Git repository containing the source code for this package.
  git: 'https://github.com/pablor21/accounts-password-phone',
  // By default, Meteor will default to using README.md for documentation.
  // To avoid submitting documentation, set this field to null.
  documentation: 'README.md'
});


Npm.depends({
  "phone"         : "2.2.0",
  "stream-buffers": "3.0.2"
});

Package.onUse(api => {
  api.versionsFrom('1.8');
  api.use('npm-bcrypt', 'server');

  api.use([
    'accounts-base',
    'accounts-password',
    'srp',
    'sha',
    'ejson',
    'ddp'
  ], ['client', 'server']);

  // Export Accounts (etc) to packages using this one.
  api.imply('accounts-password', ['client', 'server']);

  api.use('random', 'server');
  api.use('callback-hook', 'server');
  api.use('ecmascript');
  api.use('check');
  api.addFiles('sms_server.js', 'server');
  api.export('SMS', 'server');
  api.export('SMSTest', 'server', { testOnly: true });

  api.addFiles('sms_templates.js', 'server');
  api.addFiles('phone_server.js', 'server');
  api.addFiles('phone_client.js', 'client');
});

Package.onTest(function (api) {
  api.use('ecmascript');
  api.use('tinytest');
  api.use('pablor21:accounts-password-phone');
  api.mainModule('accounts-password-phone-tests.js');
});
