import { Meteor } from 'meteor/meteor';
import { Accounts } from 'meteor/accounts-base';
import { solveRegistrationChallenge, solveLoginChallenge } from '@webauthn/client';

import {resetPasswordChallengeHandler, registrationChallengeHandlerU2F, registerCompletionHandlerU2F, loginChallengeHandler, loginCompletionHandlerU2F, loginCompletionHandlerOTP } from './method-names';

let solve = async function (c) {
    let {challengeId, challengeSecret, assertionChallenge} = c;
    
    let credentials;
    try {
        credentials = await solveLoginChallenge(assertionChallenge);
    }
    catch(e) {
        if(e.name === "NotAllowedError") {
            throw new Meteor.Error("user-cancelled", "The user cancelled the request or the request timed out");
        }
    }
    
    return {challengeId, challengeSecret, credentials};
};

let registerMFA = () => new Promise((resolve, reject) => {
    Meteor.call(registrationChallengeHandlerU2F(), async (err, res) => {
        if(err) {
            return reject(err);
        }
        
        let credentials;
        try {
            res.authenticatorSelection = {authenticatorAttachment:"cross-platform"};
            credentials = await solveRegistrationChallenge(res);
        }
        catch(e) {
            if(e.name === "NotAllowedError") {
                return reject(new Meteor.Error("user-cancelled", "The user cancelled the request or the request timed out"));
            }
            return reject(e);
        }
        
        Meteor.call(registerCompletionHandlerU2F(), credentials, (err, res) => {
            if(err) {
                reject(err);
            }
            else {
                resolve();
            }
        });
    });
});


let finishResetPassword = (finishLoginParams, code) => new Promise(async (resolve, reject) => {
    let {res, token, newPassword} = finishLoginParams;
    
    if (!token instanceof String) {
        return reject(new Meteor.Error(400, "Token must be a string"));
    }

    if (!newPassword instanceof String) {
        return reject(new Meteor.Error(400, "Password must be a string"));
    }

    if (!newPassword) {
        return reject(new Meteor.Error(400, "Password may not be empty"));
    }

    let methodArguments = [token, Accounts._hashPassword(newPassword)];
    
    if(res.method === "u2f") {
        let assertion = await solve(res);
        methodArguments.push(assertion);
    }

    if(res.method === "otp") {
        if(!code) {
            return reject(new Meteor.Error("otp-required", "An OTP is required"));
        }
        
        methodArguments.push({...res, code});
    }
    
    Accounts.callLoginMethod({
        methodName: 'resetPassword',
        methodArguments,
        userCallback:(err) => {
            if(err) {
                console.error("resetPassword:Accounts.callLoginMethod", err);
                reject(err);
            }
            else {
                resolve();
            }
        }
    });
});

let resetPasswordWithMFA = (token, newPassword) => new Promise((resolve, reject) => {
    Meteor.call(resetPasswordChallengeHandler(), async (err, res) => {
        if(err) {
            console.error("resetPasswordChallengeHandler", err);
            return reject(err);
        }
        
        let finishLoginParams = {token, newPassword, res, _type:"resetPassword"};
        
        resolve({method:res.method, finishLoginParams, finishParams:finishLoginParams});
    });
});

let resetPassword = (token, newPassword) => new Promise((resolve, reject) => {
    Meteor.call(resetPasswordChallengeHandler(), token, err => {
        if(err) {
            if(err.error === "no-mfa-required") {
                Accounts.resetPassword(token, newPassword, err => {
                    if(err) {
                        reject(err);
                    }
                    else {
                        resolve(err);
                    }
                });
            }
            else {
                reject(err);
            }
        }
        else {
            resetPasswordWithMFA(token, newPassword).then(resolve).catch(reject);
        }
    });
});


let finishLogin = (finishLoginParams, code) => new Promise(async (resolve, reject) => {
    let {res} = finishLoginParams;
    let methodName, methodArguments = [];
    
    if(res.method === "u2f") {
        let assertion = await solve(res);
        methodArguments.push(assertion);
        methodName = loginCompletionHandlerU2F();
    }

    if(res.method === "otp") {
        if(!code) {
            return reject(new Meteor.Error("otp-required", "An OTP is required"));
        }
        
        methodArguments.push({...finishLoginParams.res, code});
        methodName = loginCompletionHandlerOTP();
    }
    
    Accounts.callLoginMethod({
        methodName,
        methodArguments,
        userCallback:(err) => {
            if(err) {
                reject(err);
            }
            else {
                resolve();
            }
        }
    });
});

let loginWithMFA = (username, password) => new Promise((resolve, reject) => {
    Meteor.call(loginChallengeHandler(), username, Accounts._hashPassword(password), async (err, res) => {
        if(err) {
            return reject(err);
        }
        
        let finishLoginParams = {res, _type:"login"};
        
        resolve({method:res.method, finishLoginParams, finishParams:finishLoginParams});
    });
});

let login = (username, password) => new Promise((resolve, reject) => {
    Meteor.loginWithPassword(username, password, err => {
        if(err) {
            if(err.error === "mfa-required") {
                loginWithMFA(username, password).then(resolve).catch(reject);
            }
            else {
                reject(err);
            }
        }
        else {
            resolve({method:null});
        }
    });
});

export default {
    solve,
    registerMFA, registerU2F:registerMFA,
    
    finishResetPassword,
    resetPasswordWithMFA,
    resetPassword,
    
    finishLogin,
    loginWithMFA,
    login,
};