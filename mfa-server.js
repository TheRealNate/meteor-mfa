import { Meteor } from 'meteor/meteor';
import { Mongo } from 'meteor/mongo';
import { check, Match } from 'meteor/check';
import { Accounts } from 'meteor/accounts-base';
import { Random } from 'meteor/random';
import crypto from 'crypto';
import { authenticator } from 'otplib';

import { parseLoginRequest, parseRegisterRequest, generateRegistrationChallenge, generateLoginChallenge, verifyAuthenticatorAssertion } from '@webauthn/server';
import {authorizeActionChallengeHandler, authorizeActionCompletionHandler, resetPasswordCheckMFARequired, registrationChallengeHandlerTOTP, registrationCompletionHandlerTOTP, loginCompletionHandler, resetPasswordChallengeHandler, registrationChallengeHandlerU2F, registerCompletionHandlerU2F, loginChallengeHandler } from './method-names';

let MFARegistrations = new Mongo.Collection("mfaregistrations");
let MFAChallenges = new Mongo.Collection("mfachallenges");
let MFAAuthorizations = new Mongo.Collection("mfaauthorizations");

const userQueryValidator = Match.Where(user => {
  check(user, Match.OneOf({id:Match.Optional(String)}, {username:Match.Optional(String)}, {email:Match.Optional(String)}));
  return true;
});

const generateCode = () => {
  return Array(...Array(6)).map(() => {return Math.floor(Math.random() * 10);}).join('');
};

let publicKeyCredentialSchema = {
    type:"public-key",
    id:String,
    rawId:String,
    response: {
        authenticatorData:String,
        signature:String,
        userHandle:Match.OneOf(null, String),
        clientDataJSON:String
    },
    getClientExtensionResults:Match.Optional({})
};

let solvedU2FChallengeSchema = {
    challengeId:String,
    challengeSecret:String,
    credentials:publicKeyCredentialSchema
};

let _strings = {
    mfaAlreadyEnabledError:"MFA is already enabled",
    incorrectPasswordError:"Incorrect Password",
    mfaRequiredError:"MFA is required",
    mfaFailedError:"Failed to authenticate with MFA"
};
let _defaults = {
    mfaDetailsField:"mfa",
    challengeExpiry:(1000 * 60),
    getUserDetails:(userId) => {
        return { id:userId, name:userId };
    },
    onFailedAssertion:() => {},
    enableU2F:true,
    enableTOTP:true,
    enableOTP:false,
    onSendOTP:null,
    requireResetPasswordMFA:true,
    allowU2FAuthorization:true,
    authorizationDisabledMethods:[],
    keepChallenges:false,
    passwordless:false
};

let config = Object.assign({}, _defaults);
let strings = Object.assign({}, _strings);

let setConfig = function (c) {
    Object.assign(config, c);
};

let setStrings = function (s) {
    Object.assign(strings, s);
};

const errors = {
    mfaRequired:new Meteor.Error("mfa-required", strings.mfaRequiredError),
    mfaFailed:new Meteor.Error("mfa-failed", strings.mfaFailedError),
    badMfaRequest:new Meteor.Error(400)
};

let mfaMethods = ["u2f", "otp", "totp"];

let isExpired = function (expiryDate) {
    if(!expiryDate instanceof Date) {
        throw new Error("Expiry date is not a Date");
    }
        
    return new Date() >= expiryDate;
};

let generateChallenge = function (userId, type, challengeConnectionHash) {
    let user = Meteor.users.findOne({_id:userId}, {fields:{"services.mfapublickey":1, "services.mfaenabled":1, "services.mfamethod":1}});
    
    if(!user || !user.services.mfaenabled) {
        throw new Meteor.Error(400);
    }
    
    check(user.services.mfamethod, Match.OneOf(...mfaMethods));
    
    let response, challengeData;
    if(user.services.mfamethod === "u2f") {
        response = {assertionChallenge:generateLoginChallenge(user.services.mfapublickey)};
        challengeData = {challenge:response.assertionChallenge.challenge};
    }
    if(user.services.mfamethod === "otp") {
        response = {};
        challengeData = {code:generateCode()};
        config.onSendOTP(userId, challengeData.code);
    }
    if(user.services.mfamethod === "totp") {
        response = {}, challengeData = {};
    }
    
    let challengeSecret = Random.secret(50);
    let challengeId = MFAChallenges.insert({
        type,
        userId:user._id,
        expires:new Date(new Date().valueOf() + config.challengeExpiry),
        method:user.services.mfamethod,
        connectionHash:challengeConnectionHash,
        challengeSecret,
        used:false,
        ...challengeData
    });
    
    return {challengeId, challengeSecret, method:user.services.mfamethod, ...response};    
};

let verifyAssertion = function (type, {challengeId, credentials}) {
    check(credentials, publicKeyCredentialSchema);
    
    let challengeObj = MFAChallenges.findOne({_id:challengeId});
    
    const { challenge, keyId } = parseLoginRequest(credentials);
    
    let user = Meteor.users.findOne({_id:challengeObj.userId});
    
    if(
        !challengeObj
        || challengeObj.expires < new Date()
        || challengeObj.type !== type
        || challengeObj.challenge !== challenge
        || user.services.mfapublickey.credID !== keyId
    ) {
        config.onFailedAssertion && config.onFailedAssertion(this);
        throw new Meteor.Error(403);
    }
    
    const loggedIn = verifyAuthenticatorAssertion(credentials, user.services.mfapublickey);
    
    return loggedIn;
};

let disableMFA = function (userId) {
    check(userId, String);
    Meteor.users.update({_id:userId}, {$unset:{"services.passwordlessenabled":true, "services.mfapublickey":true, "services.mfamethod":true}, $set:{"services.mfaenabled":false, [config.mfaDetailsField + ".enabled"]:false, [config.mfaDetailsField + ".type"]:null}});
};

let disablePasswordless = function (userId) {
    check(userId, String);
    Meteor.users.update({_id:userId}, {$unset:{"services.passwordlessenabled":true}, $set:{[config.mfaDetailsField + ".passwordless"]:false}});
};

let enableOTP = function (userId) {
    let user = Meteor.users.findOne({_id:userId}, {fields:{"services.mfaenabled":1}});
    
    if(user.services && user.services.mfaenabled === true) {
        throw new Meteor.Error(400, strings.mfaAlreadyEnabledError);
    }
    
    Meteor.users.update({_id:userId}, {$set:{
        [config.mfaDetailsField]:({enabled:true, type:"otp"}),
        "services.mfaenabled":true,
        "services.mfamethod":"otp"
    }});    
};

const SHA256 = function (str) {
    const hash = crypto.createHash('sha256');
    hash.update(str);
    return hash.digest('base64');    
};

const createConnectionHash = function (connection) {
    let str = "";
    if(config.enforceMatchingConnectionId) {
        str += connection.id;
    }
    if(config.enforceMatchingClientAddress) {
        str += connection.clientAddress;
    }
    if(config.enforceMatchingUserAgent) {
        str += connection.httpHeaders["user-agent"];
    }
    return SHA256(str);
};

let u2fAuthorizationIsValid = function (authorization) {
    return authorization instanceof Object && !authorization.used && !isExpired(authorization.expires) && authorization.authenticated === true;
};

let invalidateU2FAuthorization = function (authorizationId) {
    MFAAuthorizations.update({_id:authorizationId}, {$set:{
        used:true,
        authenticated:false,
        useDate:new Date()
    }});
}

const invalidateChallenge = function (challengeId) {
    if(config.keepChallenges) {
        MFAChallenges.update({_id:challengeId}, {$set:{used:true}});
    }
    else {
        MFAChallenges.remove({_id:challengeId});
    }
};

const verifyChallenge = function (type, params) {
    let {challengeId, challengeSecret} = params;
    check(challengeId, String);
    check(challengeSecret, String);
    
    let challengeConnectionHash = createConnectionHash(this.connection);
    let challengeObj = MFAChallenges.findOne({_id:challengeId});
    
    if(
        !challengeObj
        || challengeObj.type !== type
        || challengeObj.connectionHash !== challengeConnectionHash
        || challengeObj.challengeSecret !== challengeSecret
        || challengeObj.expires < new Date()
        || challengeObj.used === true
    ) {
        throw new Meteor.Error(404);
    }
    
    let user = Meteor.users.findOne({_id:challengeObj.userId});
    
    let loggedIn = false;
    if(user.services.mfamethod === "u2f") {
        if(typeof(params.U2FAuthorizationCode) === "string") {
            check(params, {challengeId:String, challengeSecret:String, U2FAuthorizationCode:String});
            let authorization = MFAAuthorizations.findOne({$and:[{action:type}, {userId:user._id}, {code:params.U2FAuthorizationCode}]});
            loggedIn = u2fAuthorizationIsValid(authorization);
            if(loggedIn) {
                invalidateU2FAuthorization(authorization._id);
            }
        }
        else {
            check(params, {challengeId:String, challengeSecret:String, credentials:publicKeyCredentialSchema});
            loggedIn = verifyAssertion(type, params);
        }
    }
    if(user.services.mfamethod === "otp") {
        check(params.code, String);
        loggedIn = challengeObj.code === params.code;
    }
    if(user.services.mfamethod === "totp") {
        check(params.code, String);
        loggedIn = authenticator.check(params.code, user.services.mfasecret);
    }
    
    if(!loggedIn) {
        throw new Meteor.Error(403);
    }
        
    invalidateChallenge(challengeId);

    return user._id;
};

Meteor.methods({
    [registrationChallengeHandlerTOTP()]: async function () {
        if(!config.enableTOTP) return;

        if(!this.userId) {
            throw new Meteor.Error(403);
        }
        
        const secret = authenticator.generateSecret();

        let registrationId = MFARegistrations.insert({
            secret,
            userId:this.userId,
            method:"totp"
        });
        
        return {registrationId, secret};
    },
    [registrationCompletionHandlerTOTP()]: async function ({registrationId, token}) {
        if(!config.enableTOTP) return;
        
        check(registrationId, String);
        check(token, String);

        if(!this.userId) {
            throw new Meteor.Error(403);
        }
        
        let registration = MFARegistrations.findOne({$and:[{userId:this.userId}, {_id:registrationId}]});
        
        if(!registration) {
            throw new Meteor.Error(404);
        }
        
        if(!authenticator.check(token, registration.secret)) {
            throw new Meteor.Error(403, "Incorrect Token");
        }
        
        Meteor.users.update({_id:this.userId}, {$set:{
            [config.mfaDetailsField]:({enabled:true, type:"totp"}),
            "services.mfasecret":registration.secret,
            "services.mfaenabled":true,
            "services.mfamethod":"totp"
        }});        
        
        MFARegistrations.remove({_id:registration._id});
        
        return 200;
    },

    [registrationChallengeHandlerU2F()]: async function (params) {
        if(!config.enableU2F) return;
        
        try {
            check(params, {passwordless:true, password:{digest:String, algorithm:"sha-256"}});
            check(config.passwordless, true);
        }
        catch(e) {
            check(params, {passwordless:false});
        }
        
        if(!this.userId) {
            throw new Meteor.Error(403);
        }
        
        try {
            check(config.rp, {id:String, name:String});
        }
        catch(e) {
            throw new Error("config.rp has not been set. Must be set to {id:'your.domain.com', name:'Your App Name'}. Use MFA.setConfig({rp:{<...>}})");
        }
        
        if(typeof(config.getUserDetails) !== "function") {
            throw new Error(`config.getUserDetails should be a function: userId => ({id:"an id", name:"user's name"})`);
        }
        
        const challengeResponse = generateRegistrationChallenge({
            relyingParty:config.rp,
            user:config.getUserDetails(this.userId)
        });
        
        if(params.passwordless) {
            let user = Meteor.users.findOne({_id:this.userId});
            let checkPassword = Accounts._checkPassword(user, params.password);
            if (checkPassword.error) {
              throw new Meteor.Error(403, strings.incorrectPasswordError);
            }
        }
        
        MFARegistrations.insert({
            challenge:challengeResponse.challenge,
            userId:this.userId,
            method:"u2f",
            passwordless:params.passwordless
        });
        
        return challengeResponse;
    },
    [registerCompletionHandlerU2F()]: async function (credentials) {
        if(!config.enableU2F) return;
        
        if(!this.userId) {
            throw new Meteor.Error(403);
        }
        
        const { key, challenge } = parseRegisterRequest(credentials);
        
        let registration = MFARegistrations.findOne({$and:[{userId:this.userId}, {challenge}]});
        
        if(!registration) {
            throw new Meteor.Error(404);
        }
        
        let user = Meteor.users.findOne({_id:this.userId}, {fields:{"services.mfaenabled":1, "services.passwordlessenabled":1}});
        
        if(user.services.mfaenabled === true && (!registration.passwordless || user.services.passwordlessenabled)) {
            throw new Meteor.Error(400, strings.mfaAlreadyEnabledError);
        }
        
        Meteor.users.update({_id:this.userId}, {$set:{
            [config.mfaDetailsField]:({enabled:true, type:"u2f", passwordless:registration.passwordless}),
            "services.mfapublickey":key,
            "services.mfaenabled":true,
            "services.mfamethod":"u2f",
            "services.passwordlessenabled":registration.passwordless
        }});
        
        MFARegistrations.remove({_id:registration._id});
        
        return 200;
    },
    [resetPasswordCheckMFARequired()]: async function (token) {
        check(token, String);
        
        const user = Meteor.users.findOne(
            {"services.password.reset.token": token},
            {fields: {services: 1, emails: 1}}
        );
        
        if(!user) {
            throw new Meteor.Error("token-expired", "Your reset password token has expired");
        }
        
        if(user.services.mfaenabled) {
            return true;
        }
        return false;
    },
    [resetPasswordChallengeHandler()]: async function (token) {
        check(token, String);
        
        const user = Meteor.users.findOne(
            {"services.password.reset.token": token},
            {fields: {services: 1, emails: 1}}
        );
        
        if(!user) {
            throw new Meteor.Error("token-expired", "Your reset password token has expired");
        }
        
        if(!user.services.mfaenabled) {
            throw new Meteor.Error("no-mfa-required");
        }
        
        let challengeConnectionHash = createConnectionHash(this.connection);
        return generateChallenge(user._id, "resetPassword", challengeConnectionHash);
    },
    [loginChallengeHandler()]: async function (username, password) {
        if(typeof(username) === "string") {
            if(username.includes("@")) {
                username = {email:username};
            }
            else {
                username = {username};
            }
        }
        
        check(username, userQueryValidator);
        check(password, Match.OneOf({passwordless:true}, {digest:String, algorithm:"sha-256"}));
        
        let user = Accounts._findUserByQuery(username);
        
        if(!user) {
            throw new Meteor.Error(404);
        }
        
        if(!user.services.mfaenabled) {
            throw new Meteor.Error("not-mfa", "Not MFA");
        }
        
        if(password.passwordless) {
            try {
                check(user.services.passwordlessenabled, true);
                check(config.passwordless, true);
            }
            catch(e) {
                throw new Meteor.Error("not-passwordless", "Not Passwordless");
            }
        }
        else {
            let checkPassword = Accounts._checkPassword(user, password);
            if (checkPassword.error) {
              throw new Meteor.Error(403, strings.incorrectPasswordError);
            }
        }
        
        let challengeConnectionHash = createConnectionHash(this.connection);
        return generateChallenge(user._id, "login", challengeConnectionHash);
    },
    [loginCompletionHandler()]: async function (params) {
        check(params, Object);
        check(params.challengeId, String);
        check(params.challengeSecret, String);
        
        let userId = verifyChallenge("login", params);
        
        return Accounts._attemptLogin(this, 'login', '', {
          type: 'mfa',
          userId,
        });
    },
    [authorizeActionChallengeHandler()]: async function (type) {
        if(!config.allowU2FAuthorization) {return;}
        
        if(config.authorizationDisabledMethods.includes(type)) {
            throw new Meteor.Error(400, "This method cannot be authorized by one-time-code");
        }
        
        check(type, String);
        
        if(type === "resetPassword") {
            throw new Meteor.Error(400, "Type resetPassword is not supported");
        }
        
        let user = Meteor.user();
        
        if(!user) {
            throw new Meteor.Error(404);
        }
        
        if(!user.services.mfaenabled) {
            throw new Meteor.Error(400);
        }
        
        if(user.services.mfamethod !== "u2f") {
            throw new Meteor.Error(400, "This method is only supported for accounts with u2f MFA");
        }
        
        let challengeConnectionHash = createConnectionHash(this.connection);
        let authorizationId = MFAAuthorizations.insert({
            action:type,
            userId:this.userId,
            authenticated:false,
            expires:new Date(new Date().valueOf() + 1000 * 60 * 10)
        });
        
        return {authorizationId, challenge:generateChallenge(user._id, ("authorize:" + authorizationId), challengeConnectionHash)}; 
    },
    [authorizeActionCompletionHandler()]: async function (authorizationId, solvedU2FChallenge) {
        if(!config.allowU2FAuthorization) {return;}
        
        check(authorizationId, String);
        check(solvedU2FChallenge, solvedU2FChallengeSchema);
        
        let authorization = MFAAuthorizations.findOne({_id:authorizationId});
        
        if(!this.userId || !authorization || isExpired(authorization.expires) || authorization.userId !== this.userId) {
            throw new Meteor.Error(400);
        }
        
        verifyChallenge(("authorize:" + authorizationId), solvedU2FChallenge);
        
        let code = generateCode();
        
        MFAAuthorizations.update({_id:authorizationId}, {$set:{
            authenticated:true,
            code
        }});
        
        return {code};
    }
});

Accounts.validateLoginAttempt(options => {
    if(!options.allowed) {
        return false;
    }
    
    if(options.type === 'resume' || options.type === "createUser") {
        return true;
    }

    if(options.type === 'mfa' && options.methodName === 'login') {
        return options.allowed;
    }
    
    if(options.methodName === 'resetPassword') {
        if(config.requireResetPasswordMFA && options.user.services.mfaenabled) {
            try {
                check(options.methodArguments[2], Object);
                check(options.methodArguments[2].challengeId, String);
                check(options.methodArguments[2].challengeSecret, String);
            }
            catch(e) {
                throw errors.mfaRequired;
            }
            
            let params = options.methodArguments[2];
            
            try {
                verifyChallenge("resetPassword", params);
                return true;
            }
            catch(e) {
                throw errors.mfaFailed;
            }
        }
        else {
            return true;
        }
    }
  
    if(options.user.services.mfaenabled) {
        throw errors.mfaRequired;
    }
  
    return true;
});

let getCurrentTOTP = function (secret) {
    return authenticator.generate(secret);
};

export default { disablePasswordless, verifyChallenge, getCurrentTOTP, enableOTP, setConfig, setStrings, disableMFA, generateChallenge, verifyAssertion, verifyAttestation:verifyAssertion };
