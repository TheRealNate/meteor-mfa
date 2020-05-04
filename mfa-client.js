import { Meteor } from 'meteor/meteor';
import { Accounts } from 'meteor/accounts-base';
import { solveRegistrationChallenge, solveLoginChallenge } from '@webauthn/client';

import {registrationChallengeHandlerTOTP, registrationCompletionHandlerTOTP, resetPasswordChallengeHandler, registrationChallengeHandlerU2F, registerCompletionHandlerU2F, loginChallengeHandler, loginCompletionHandler } from './method-names';

let solveU2FChallenge = async function (c) {
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

let assembleChallengeCompletionArguments = async function (finishLoginParams, code) {
    let {res} = finishLoginParams;
    let methodArguments = [];
    
    if(res.method === "u2f") {
        let assertion = await solveU2FChallenge(res);
        methodArguments.push(assertion);
    }

    if(res.method === "otp" || res.method === "totp") {
        if(!code) {
            throw new Meteor.Error("otp-required", "An OTP is required");
        }
        
        methodArguments.push({...res, code});
    }    
    
    return methodArguments;
};

let solveChallenge = async function (challenge, code) {
    let solvedChallenge = assembleChallengeCompletionArguments({res:challenge}, code)[0];
    return solvedChallenge;
};

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
    methodArguments.concat(await assembleChallengeCompletionArguments(finishLoginParams, code));
    
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
    let methodName = loginCompletionHandler();
    let methodArguments = await assembleChallengeCompletionArguments(finishLoginParams, code);
    
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

let finishRegisterTOTP = (token, registrationId) => new Promise((resolve, reject) => {
    Meteor.call(registrationCompletionHandlerTOTP(), {registrationId, token}, err => {
        if(err) {
            reject(err);
        }
        else {
            resolve();
        }
    });
});

let registerTOTP = () => new Promise((resolve, reject) => {
    Meteor.call(registrationChallengeHandlerTOTP(), (err, res) => {
        if(err) {
            reject(err);
        }
        else {
            resolve(res);
        }
    });
});

export default {
    solveChallenge,
    solveU2FChallenge,
    registerMFA, registerU2F:registerMFA,
    
    finishResetPassword,
    resetPasswordWithMFA,
    resetPassword,
    
    finishLogin,
    loginWithMFA,
    login,
    
    finishRegisterTOTP,
    registerTOTP,
    
    // DEPRECATED in 0.0.3
    solve:solveU2FChallenge,
};