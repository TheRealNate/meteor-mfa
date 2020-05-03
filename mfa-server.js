import { Meteor } from 'meteor/meteor';
import { Mongo } from 'meteor/mongo';
import { check, Match } from 'meteor/check';
import { Accounts } from 'meteor/accounts-base';
import { Random } from 'meteor/random';
import crypto from 'crypto';

import { parseLoginRequest, parseRegisterRequest, generateRegistrationChallenge, generateLoginChallenge, verifyAuthenticatorAssertion } from '@webauthn/server';

let MFARegistrations = new Mongo.Collection("mfaregistrations");
let MFAChallenges = new Mongo.Collection("mfachallenges");

import {resetPasswordChallengeHandler, registrationChallengeHandlerU2F, registerCompletionHandlerU2F, loginChallengeHandler, loginCompletionHandlerU2F, loginCompletionHandlerOTP } from './method-names';

const userQueryValidator = Match.Where(user => {
  check(user, Match.OneOf({id:Match.Optional(String)}, {username:Match.Optional(String)}, {email:Match.Optional(String)}));
  return true;
});

const generateCode = () => {
  return Array(...Array(6))
    .map(() => {
      return Math.floor(Math.random() * 10);
    })
    .join('');
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

let _strings = {
    mfaAlreadyEnabledError:"MFA is already enabled",
    incorrectPasswordError:"Incorrect Password"
};
let _defaults = {
    mfaDetailsField:"mfa",
    challengeExpiry:(1000 * 60),
    getUserDetails:(userId) => {
        let user = Meteor.users.findOne({_id:userId}, {fields:{username:1}});
        return { id:userId, name:user.username };
    },
    onFailedAssertion:() => {},
    enableU2F:true,
    enableOTP:false,
    onSendOTP:null
};

let config = Object.assign({}, _defaults);
let strings = Object.assign({}, _strings);

let setConfig = function (c) {
    Object.assign(config, c);
};

let setStrings = function (s) {
    Object.assign(strings, s);
};

let mfaMethods = ["u2f", "otp"];

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
    
    let challengeSecret = Random.secret(50);
    let challengeId = MFAChallenges.insert({
        type,
        userId:user._id,
        expires:new Date(new Date().valueOf() + config.challengeExpiry),
        method:user.services.mfamethod,
        connectionHash:challengeConnectionHash,
        challengeSecret,
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
    Meteor.users.update({_id:userId}, {$unset:{"services.mfapublickey":true, "services.mfamethod":true}, $set:{"services.mfaenabled":false, [config.mfaDetailsField + ".enabled"]:false, [config.mfaDetailsField + ".type"]:null}});
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

Meteor.methods({
    [registrationChallengeHandlerU2F()]: async function () {
        if(!config.enableU2F) return;
        
        if(!this.userId) {
            throw new Meteor.Error(403);
        }
        
        try {
            check(config.rp, {id:String, name:String});
        }
        catch(e) {
            throw new Error("config.rp has not been set. Must be set to {id:'your.domain.com', name:'Your App Name'}. Use MFA.setConfig({rp:{<...>}})");
        }
        
        const challengeResponse = generateRegistrationChallenge({
            relyingParty:config.rp,
            user:config.getUserDetails(this.userId)
        });
        
        MFARegistrations.insert({
            challenge:challengeResponse.challenge,
            userId:this.userId,
            method:"u2f"
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
        
        let user = Meteor.users.findOne({_id:this.userId}, {fields:{"services.mfaenabled":1}});
        
        if(user.services.mfaenabled === true) {
            throw new Meteor.Error(400, strings.mfaAlreadyEnabledError);
        }
        
        Meteor.users.update({_id:this.userId}, {$set:{
            [config.mfaDetailsField]:({enabled:true, type:"u2f"}),
            "services.mfapublickey":key,
            "services.mfaenabled":true,
            "services.mfamethod":"u2f"
        }});
        
        return 200;
    },
    [resetPasswordChallengeHandler()]: async function (token) {
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
        check(password, Object);
        
        let user = Accounts._findUserByQuery(username);
        
        if(!user) {
            throw new Meteor.Error(404);
        }
        
        if(!user.services.mfaenabled) {
            throw new Meteor.Error(400);
        }
        
        let checkPassword = Accounts._checkPassword(user, password);
        if (checkPassword.error) {
          throw new Meteor.Error(403, strings.incorrectPasswordError);
        }
        
        let challengeConnectionHash = createConnectionHash(this.connection);
        return generateChallenge(user._id, "login", challengeConnectionHash);
    },
    [loginCompletionHandlerU2F()]: async function (params) {
        let {challengeId, challengeSecret, credentials} = params;
        check(challengeId, String);
        check(challengeSecret, String);
        
        let challengeObj = MFAChallenges.findOne({_id:challengeId});
        
        if(!challengeObj || challengeObj.challengeSecret !== challengeSecret || challengeObj.expires < new Date() || challengeObj.type !== "login" || challengeObj.method !== "u2f") {
            throw new Meteor.Error(404);
        }
        
        let user = Meteor.users.findOne({_id:challengeObj.userId});
        
        const loggedIn = verifyAssertion("login", {challengeId, credentials});
        
        let challengeConnectionHash = createConnectionHash(this.connection);
        if(!loggedIn || challengeObj.connectionHash !== challengeConnectionHash) {
            throw new Meteor.Error(403);
        }
        
        return Accounts._attemptLogin(this, 'login', '', {
          type: 'mfa',
          userId: user._id,
        });
    },
    [loginCompletionHandlerOTP()]: function ({challengeId, challengeSecret, code}) {
        check(challengeId, String);
        check(challengeSecret, String);
        check(code, String);
        
        let challengeObj = MFAChallenges.findOne({_id:challengeId});
        
        if(!challengeObj || challengeObj.challengeSecret !== challengeSecret || challengeObj.expires < new Date() || challengeObj.type !== "login" || challengeObj.method !== "otp") {
            throw new Meteor.Error(400);
        }
        
        let challengeConnectionHash = createConnectionHash(this.connection);
        if(challengeObj.code !== code || challengeObj.connectionHash !== challengeConnectionHash) {
            throw new Meteor.Error(403);
        }
        
        let user = Meteor.users.findOne({_id:challengeObj.userId});
        
        return Accounts._attemptLogin(this, 'login', '', {
          type: 'mfa',
          userId: user._id,
        });
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
    
    if(options.methodName === 'resetPassword' && config.requireResetPasswordMFA) {
        try {
            check(options.methodArguments[2], Object);
            check(options.methodArguments[2].challengeId, String);
        }
        catch(e) {
            throw new Meteor.Error("mfa-required", "MFA verification required");
        }
        
        try {
            let challengeObj = MFAChallenges.findOne({_id:options.methodArguments[2].challengeId});
            
            let challengeConnectionHash = createConnectionHash(options.connection);
            if(!challengeObj || challengeObj.type !== "resetPassword" || challengeObj.connectionHash !== challengeConnectionHash) {
                throw new Meteor.Error(400);
            }
            
            if(options.user.services.mfamethod === "u2f") {
                check(options.methodArguments[2].credentials, publicKeyCredentialSchema);
                let isValid = verifyAssertion("resetPassword", options.methodArguments[2]);
                if(!isValid) {
                    throw new Meteor.Error("mfa-error");
                }
                else {
                    return true;
                }
            }
            else {
                check(options.methodArguments[2].code, String);
                
                if(challengeObj.method !== "otp") {
                    throw new Meteor.Error(400);
                }
                
                if(challengeObj.code !== options.methodArguments[2].code) {
                    throw new Meteor.Error("mfa-error");
                }
                else {
                    return true;
                }
            }
        }
        catch(e) {
            throw new Meteor.Error("mfa-failed", "MFA verification failed");
        }
    }
  
    if(options.user.services.mfaenabled) {
        throw new Meteor.Error("mfa-required");
    }
  
    return true;
});

export default { enableOTP, setConfig, setStrings, disableMFA, generateChallenge, verifyAssertion, verifyAttestation:verifyAssertion };
