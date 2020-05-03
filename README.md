Multi-Factor Authentication for Meteor, supporting U2F hardware keys as well as OTPs.

This package is still in development and may contain issues. We'd appreciate you reviewing the code and creating any issue if you see any.

#### What is U2F?

This package was created to add support for U2F aka hardware keys. Hardware keys are widely regarded as the strongest form of multi factor authentication. They require the user plugs a physical key into their device in order to login to a website. This also includes built in anti-phishing security, if a key is used to authenticate on the wrong domain (go0gle.com instead of google.com), the signature it produces will be invalid to the intended domain. This means, barring a compromised device/browser, its very difficult for phishers to attack users who use U2F keys.

This package also supports OTPs (codes delivered via SMS, email, etc).

#### Known Issues
- Password Resets that fail MFA authentication will still expire token (e.g. if used has a typo in their code they will require a new token)

#### Roadmap
If you are interested in contributing on any of these tasks please reach out!

- Create `meteor-react-native` companion package
- Implement Automated Testing
- Support Recovery Keys (Keys generated at time of setting up MFA which can be used when no other method is available)
- Add "Login other device" support: generate an OTP from a device capable of using U2F to be entered on a device not capable of U2F
- Support TOTPs (Google Authenticator, Authy)
- Support requiring more then 2 factors to authenticate

## Installation/Setup

Add the package with `meteor add ndev:mfa`

You can then follow the instructions below for setting up U2F and/or OTP.

*Note that U2F is enabled by default, and OTP is disabled by default*

### Universal 2nd Factor (U2F)

First, Set required configuration fields on server:
````
import MFA from 'meteor/ndev:mfa';

MFA.setConfig({
  rp:{
    id:"thedomain.of.your.app",
    name:"My App"
  }
});
````

And add the ability for users to enable MFA from the client
````
import MFA from 'meteor/ndev:mfa';

MFA.registerU2F().then(r => {
  alert("MFA is now turned on!");
}).catch(err => {
  alert("Something went wrong");
});
````

### One Time Passwords (OTPs)

One-Time-Passwords are codes typically sent via SMS or Email. This package takes a very simplistic approach to enrollment in order to let you control how the codes get delivered.

First, enable OTP in the config, and define a function for sending codes:
````
MFA.setConfig({
  enableOTP:true,
  onSendOTP:(userId, code) => {...}
})
````

And simply call this function from the server to enable OTP MFA for a user (note that it will fail if MFA is already enabled):
````
MFA.enableOTP(userId);
````

Since you have full control over how a code is sent, it is up to you to maintain the user's prefered method of delivery.

### Logging in a user

The package provides a method called `MFA.login`. This method will attempt to login the user normally, then if it fails due to mfa being required, runs `MFA.loginWithMFA`. If you prefer, you can customize your implementation by doing your own check to see if MFA exists then, if it does, directly calling `MFA.loginWithMFA`.

There are two steps to logging in with MFA:
1. Perform the first-factor login (password), and retrieve the MFA method
2. Obtain any necessary information from the user and finish the login

The flow has been designed this way so that the implementation for U2F and OTP (one-time-password/code) is as similar as possible.

First, you call `MFA.login` with your username/email and password. This will resolve with an object containing the method and a field called finishLoginParams, which can be stored to be passed to finishLoginParams later.

For U2F: you can then either immediately call `MFA.finishLogin(finishLoginParams)` or make some changes to your UI, then call it.

For OTP: you can store finishLoginParams, update your UI to collect the OTP, then once the OTP has been entered call `MFA.finishLogin`.

Here is a simple example:

````
import MFA from 'meteor/ndev:mfa';

MFA.login(username, password).then(({method, finishLoginParams}) => {
  if(method === "u2f") {
    // For U2F, you don't really need to make any changes to your UI since the pop-up will appear immediately, but you can do-so here if you wish
    MFA.finishLogin(finishLoginParams);
  }
  else {
    //
    // You can save the finishLoginParams, collect the code in your UI, then call MFA.finishLogin
    let code = prompt("What is the OTP?"); // Note that prompt should NEVER be used as it blocks the JS thread. This is just a simplified example
    MFA.finishLogin(finishLoginParams, code);
  }
}).catch(err => {
  if(err) {
    alert(err.message);
  }
});
````

You can see a complete login page example [here](/examples/react/Login.jsx)

### Publishing user's MFA status
The field specified in `config.mfaDetailsField` (default `mfa`) will contain an object with the properties enabled(Boolean) and type(String). You can publish this property to a user to allow them to check if MFA is enabled.

### Resetting Passwords with MFA
The `config.requireResetPasswordMFA` property defines whether a user must authenticate with MFA to reset their password. This is set to `false` by default.

To reset a password with MFA authentication, use the `MFA.resetPassword` method. The usage of this method is very similar to the usage of `MFA.login`:

````
MFA.resetPassword(token, newPassword).then(r => {
  if(r.method === null) {
    // The user doesn't have MFA enabled
  }
  else {
    if(method === "u2f") {
      // For U2F, you don't really need to make any changes to your UI since the pop-up will appear immediately, but you can do-so here if you wish
      MFA.finishLogin(finishLoginParams);
    }
    else {
      // You can save the finishLoginParams, collect the code in your UI, then call MFA.finishLogin
      let code = prompt("What is the OTP?"); // Note that prompt should NEVER be used as it blocks the JS thread. This is just a simplified example
      MFA.finishResetPassword(finishLoginParams, code);
    }    
  }
})
````

You should also set `config.requireResetPasswordMFA` to true. This will require that users use MFA when resetting their password.

# Full API Documentation

## Client
`import MFA from 'meteor/ndev:mfa';`

#### MFA.login(username, password)<promise>
Resolves when logged in, catches on error. This function is a wrapper for the `MFA.loginWithMFA` function. It attempts to login the user. If it receives an `mfa-required` error, it uses `MFA.loginWithMFA`. If you prefer to customize this, you can use the `MFA.loginWithMFA` function

#### MFA.loginWithMFA(username, password)<promise>
Requests a login challenge, solves it, then logs in. This function will fail if the user doesn't have MFA enabled.

#### MFA.finishLogin(finishLoginParams)<promise>
Completes a login

#### MFA.registerU2F()<promise>
Registers the user's U2F device and enables MFA

#### MFA.solve(challenge)<promise>
Solves a challenge and resolves with an attestation. Useful for server-side methods that require MFA authentication (like disabling MFA). Resolves to a attestation that can be passed to `MFA.verifyAttestation()` on the server.

### MFA.resetPassword(token, newPassword)<promise>
Resets a password using the password reset token. See "Resetting Passwords with MFA" above for usage instructions. This method works even if the user doesn't have MFA enabled.

### MFA.resetPasswordWithMFA(token, newPassword)<promise>
Like MFA.resetPassword, but will fail if user doesn't have MFA enabled

## Server
`import MFA from 'meteor/ndev:mfa';`

#### MFA.setConfig(options)
See the config options section below

#### MFA.disableMFA(userId)
Disables MFA for a user. This is an internal method. If you'd like the user to authenticate before you disable, you can do something like this:
````
Meteor.methods({
  "start:disableMFA":function () {
    let challenge = MFA.generateChallenge(this.userId, "disableMFA");
    return challenge;
  },
  
  "complete:disableMFA":function (attestation) {
    let isValid = MFA.verifyAttestation("disableMFA", attestation);
    
    if(!isValid) {
      throw new Meteor.Error(404, "Invalid Attestation");
    }
    
    MFA.disableMFA(this.userId);
  }  
});
````


#### MFA.generateChallenge(userId, type)
Generates a challenge. This is then sent to the client and passed into `MFA.solve()`

#### MFA.verifyAttestation(type, attestation)
Verifies the attestation (created by `MFA.solve` on client)

### Config Options

**mfaDetailsField *String* (default: "mfa")** The field where the mfa status object is stored (this is the field you can publish to tell whether a user has enabled)

**challengeExpiry *Number* (default: 1 minute)** How long before a challenge expires (in milliseconds)

**getUserDetails *Function(userId)* (default: `{id:user._id, name:user.username}`)** A function that returns an object with the `id` and `name` properties. The function recieves a single argument, the id of the user.

**onFailedAssertion *Function(info)* (default: none)** Function that runs when an assertion is failed. The only situation where this can be produced by the user accidentally is if the timeout expires or the wrong key is plugged into the device. Therefore, you should consider notifying the user if this happens. This function receives a single argument, which is the info argument of `Accounts.validateLoginAttempt`.

**enableU2F *Boolean* (default:true)** Enable U2F Authentication

**enableOTP *Boolean* (default:false)** Enable OTP Authentication. If this is enabled, you will need to set `config.onSendOTP`.

**onSendOTP *Function* (default: none)** Function that is called when an OTP needs to be sent. Receives the arguments `(userId, code)`.

**requireResetPasswordMFA *Boolean* (default: false)** Require MFA authentication when resetting password. This is set to false by default because you must use the custom resetPassword method should you enable this. See "Resetting Passwords with MFA" above.

**enforceMatchingConnectionId *Boolean* (default: true)** Enforce that the connection id that finishes a login challenge is the same as the one that creates it

**enforceMatchingClientAddress *Boolean* (default: true)** Enforce that the client address (IP) that finishes a login challenge is the same as the one that creates it

**enforceMatchingUserAgent *Boolean* (default: true)** Enforce that the user agent that finishes a login challenge is the same as the one that creates it
