import MFA from 'meteor/ndev:mfa';

class Login extends React.Component {
    
    state = {
        collectOTP:false
    }
    
    onCompleteLogin = () => {
        // ...
    }
    
    startLogin = () => {
        let username = document.getElementById("username").value;
        let password = document.getElementById("password").value;
        
        MFA.login(username, password).then(({method, finishLoginParams}) => {
            if(method === null) {
                // User didn't have MFA enabled. Login is complete
                this.onCompleteLogin();
            }
            else {
                if(method === "u2f") {
                    // Since the U2F key authentication is handled by the browser UI, we just immediately call MFA.finishLogin
                    MFA.finishLogin(finishLoginParams).then(this.onCompleteLogin).catch(e => alert(e.reason));
                }
                if(method === "otp") {
                    this.setState({collectOTP:true, finishLoginParams});
                }
            }
        })
    }
    
    finishLogin = () => {
        let code = document.getElementById("otp").value;
        MFA.finishLogin(this.state.loginParams, code).then(this.onCompleteLogin).catch(e => {
            if(e.error === 403) {
                alert("Invalid Code");
            }
            else {
                alert(e.reason);
            }
        });
    }
    
    render() {
        let { collectOTP } = this.state;
        
        if(collectOTP) {
            return (
                <div>
                    <h2>Enter your OTP</h2>
                    <input id="otp" placeholder="OTP"/><br/>
                    <button onClick={this.finishLogin}>Submit</button>
                </div>
            );
        }
        else {
            return (
                <div>
                    <h2>Login</h2>
                    <input id="username" placeholder="Username"/><br/>
                    <input id="password" placeholder="Password" type="password"/>
                    <button onClick={this.startLogin}>Login</button>
                </div>
            );
        }
    }
}