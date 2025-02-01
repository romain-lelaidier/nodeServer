const Crypto = {

    encrypt: (secret, message) => {
        const key = CryptoJS.enc.Hex.parse(CryptoJS.SHA256(secret).toString(CryptoJS.enc.Hex).substr(0, 64));
        const iv = CryptoJS.lib.WordArray.random(16);
        const encrypted = CryptoJS.AES.encrypt(message, key, { iv: iv });
        return iv.toString() + ':' + encrypted.ciphertext.toString(CryptoJS.enc.Hex);
    },

    decrypt: (secret, encryptedMessage) => {
        const key = CryptoJS.enc.Hex.parse(CryptoJS.SHA256(secret).toString(CryptoJS.enc.Hex).substr(0, 64));
        const textParts = encryptedMessage.split(':');
        const iv = CryptoJS.enc.Hex.parse(textParts.shift());
        const encryptedText = CryptoJS.enc.Hex.parse(textParts.join(':'));
        const decrypted = CryptoJS.AES.decrypt({ ciphertext: encryptedText }, key, { iv: iv });
        return decrypted.toString(CryptoJS.enc.Utf8);
    }

}

class Logger {

    constructor() {
        this.block = document.createElement("div");
        document.body.appendChild(this.block);

        this.log = this.log.bind(this);
        this.err = this.err.bind(this);
        this.handlePromise = this.handlePromise.bind(this);
    }

    log(message) {
        this.block.textContent = message.toString();
        console.log(">> LOG <<", message)
    }

    err(error) {
        this.block.textContent = error.toString();
        console.log(">> ERR <<", error)
    }

    handlePromise(promise) {
        promise.then(res => {
            this.log(res.message)
        }).catch(err => {
            this.err(err)
        })
    }

}

class FormResult {

    constructor(formId) {
        /*
        <div id="controllerInfo" style="display:none">
            <div id="controllerInfoText"></div>
            <div id="controllerInfoCountdown"></div>
        </div>
        */
        this.form = document.getElementById(formId)
        this.controllerInfo = document.createElement("div")
        this.controllerInfo.id = "controllerInfo"
        this.controllerInfoText = document.createElement("div")
        this.controllerInfoText.id = "controllerInfoText"
        this.controllerInfoCountdown = document.createElement("div")
        this.controllerInfoCountdown.id = "controllerInfoCountdown"
        
        document.getElementById("controller").append(this.controllerInfo)
        this.controllerInfo.append(this.controllerInfoText, this.controllerInfoCountdown)

        this.setFormDisplay(true)
        this.setControllerDisplay(false)
    }

    setFormDisplay(show) {
        if (this.form) {
            this.form.style.display = show == true ? "block" : "none";
        }
    }

    setControllerDisplay(show) {
        this.controllerInfo.style.display = show == true ? "block" : "none";
        this.controllerInfo.style.marginTop = show == true ? "12px" : "0px"
    }

    displayInfo(text) {
        this.controllerInfoText.textContent = text;
        this.setControllerDisplay(true)
        this.setFormDisplay(false)
    }

    displayError(err) {
        this.controllerInfoText.textContent = "Error : " + err.toString();
        this.setControllerDisplay(true)
        this.setFormDisplay(true)
    }

    redirectCountdown(seconds, url) {
        const getText = s => `Automatic redirection in ${s} seconds...`
        this.controllerInfoCountdown.textContent = getText(seconds);
        this.setControllerDisplay(true)
        let countdown = seconds;
        setInterval(() => {
            countdown--;
            this.controllerInfoCountdown.textContent = getText(countdown);
            if (countdown <= 0) {
                console.log(url)
                // window.location.href = url;
            }
        }, 1000);
    }

    handlePromise(promise, successMessage, seconds, url) {
        promise.then(() => {
            this.displayInfo(successMessage);
            this.redirectCountdown(seconds, url);
        }).catch(err => {
            this.displayError(err)
        })
    }

}

class User {

    constructor() {
        this.username = null;
        this.password = null;
        this.email = null;
        this.isConnected = false;
        this.token = null;
        this.tokenDuration = null;

        this.load();
    }

    load() {
        this.username = localStorage.getItem('username');
        this.email = localStorage.getItem('email');
        this.token = localStorage.getItem('token');
        this.password = localStorage.getItem('password');
        if (this.username != null && this.token != null && this.password != null) {
            this.isConnected = true;
        }
    }

    save() {
        localStorage.setItem('username', this.username);
        localStorage.setItem('email', this.email);
        localStorage.setItem('token', this.token);
        localStorage.setItem('password', this.password);
    }

    encryptPassword(password) {
        return new Promise((resolve, reject) => {
            crypto.subtle.digest(
                "SHA-384",
                new TextEncoder().encode(password)
            ).then(hashBuffer => {
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                const hashHex = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
                resolve(hashHex);
            }).catch(reject);
        });
    }

    login(username, password) {
        return new Promise((resolve, reject) => {
            this.encryptPassword(password).then(hash => {
                this.username = username;
                this.password = hash;
                this.connect()
                .then(resolve)
                .catch(error => {
                    this.username = null;
                    this.password = null;
                    reject(error);
                });
            }).catch(reject);
        })
    }

    connect() {
        return new Promise((resolve, reject) => {
            fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username: this.username,
                    password: this.password
                })
            }).then(response => {
                response.json().then(data => {
                    if (data.accessToken) {
                        this.username = data.username;
                        this.email = data.email;
                        this.token = data.accessToken;
                        this.isConnected = true;
                        this.save();
                        resolve(data);
                    } else {
                        reject(data.message);
                    }
                }).catch(reject);
            }).catch(reject);
        })
    }

    register(username, password, email) {
        return new Promise((resolve, reject) => {
            if (this.isConnected == true) return reject("Please log out first")

            this.encryptPassword(password).then(hash => {
                fetch('/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username, password: hash, email })
                }).then(response => {
                    response.json().then(data => {
                        if (response.status >= 300) reject(data.message);
                        else resolve(data);
                    }).catch(reject);
                }).catch(reject);
            }).catch(reject);
        });
    }

    verifyAccount(token) {
        return new Promise((resolve, reject) => {
            fetch('/verify/' + token, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json'
                }
            }).then(response => {
                response.json().then(data => {
                    if (response.status >= 300) reject(data.message);
                    else {
                        this.username = data.username;
                        resolve();
                    }
                }).catch(reject);
            }).catch(reject);
        })
    }

    resetPassword(token, password) {
        return new Promise((resolve, reject) => {
            this.encryptPassword(password).then(hash => {
                fetch('/reset-password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ token, newPassword: hash })
                }).then(response => {
                    response.json().then(data => {
                        if (response.status >= 300) reject(data.message);
                        else resolve(data);
                    }).catch(reject);
                }).catch(reject);
            }).catch(reject);
        })
    }

    logout() {
        localStorage.clear();
        this.load();
        this.isConnected = false;
    }

    tryFetch(url, parameters) {
        return new Promise((resolve, reject) => {
            if (this.isConnected == false) return reject("User not connected");

            fetch(url, parameters).then(response => {
                if (response.status != 401) return resolve(response);

                // try a refresh of the acces token
                fetch('/refresh-token', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        credentials: 'include',
                    },
                    body: JSON.stringify({ username: this.username })
                }).then(response => {
                    response.json().then(data => {
                        if (!data.accessToken) return reject(data.message)

                        this.token = data.accessToken;
                        this.save();
                        parameters.headers['Authorization'] = this.token;
                        fetch(url, parameters).then(resolve).catch(reject);
                    }).catch(reject);
                }).catch(reject);
            }).catch(reject);
        });
    }

    sendGameResult(score, gameType) {
        return new Promise((resolve, reject) => {
            if (this.isConnected == false) return reject("User not connected");

            this.tryFetch('/save-result', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': this.token,
                },
                body: JSON.stringify({
                    username: this.username,
                    game: Crypto.encrypt(this.username, JSON.stringify({ score, gameType }))
                })
            }).then(response => {
                if (response.status >= 300) return reject(response)
                response.json().then(resolve).catch(resolve);
            }).catch(reject);
        });
    }

    getPersonalResults() {
        return new Promise((resolve, reject) => {
            if (this.isConnected == false) return reject("User not connected");

            this.tryFetch(`/personal-results/${this.username}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': this.token,
                }
            }).then(response => {
                response.json().then(data => {
                    if (data.results) {
                        resolve(data.results);
                    } else {
                        reject(data.message);
                    }
                }).catch(reject);
            }).catch(reject);
        });
    }

    updateEmail(newEmail) {
        return new Promise((resolve, reject) => {
            if (this.isConnected == false) return reject("User not connected");

            this.tryFetch('/update-email', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': this.token
                },
                body: JSON.stringify({ username: this.username, newEmail })
            }).then(response => {
                response.json().then(data => {
                    if (response.status >= 300) reject(data.message);
                    else {
                        this.email = newEmail;
                        this.save();
                        resolve(data);
                    }
                }).catch(reject);
            }).catch(reject);
        });
    }

    updatePassword(currentPassword, newPassword) {
        return new Promise((resolve, reject) => {
            if (this.isConnected == false) return reject("User not connected");

            this.encryptPassword(currentPassword).then(currentHash => {
                this.encryptPassword(newPassword).then(newHash => {
                    this.tryFetch('/update-password', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': this.token
                        },
                        body: JSON.stringify({
                            username: this.username,
                            currentPassword: currentHash,
                            newPassword: newHash
                        })
                    }).then(response => {
                        response.json().then(data => {
                            if (response.status >= 300) reject(data.message);
                            else {
                                this.password = newHash;
                                resolve(data);
                            }
                        }).catch(reject);
                    }).catch(reject);
                });
            });
        });
    }

    removeAccount(password) {
        return new Promise((resolve, reject) => {
            if (this.isConnected == false) return reject("User not connected");
            
            this.encryptPassword(password).then(hash => {
                this.tryFetch('/remove-account', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': this.token
                    },
                    body: JSON.stringify({ username: this.username, password: hash })
                }).then(response => {
                    if (response.status === 200) this.logout()
                    response.json().then(data => {
                        if (response.status >= 300) reject(data.message);
                        else resolve(data);
                    }).catch(reject);
                }).catch(reject);
            }).catch(reject);
        });
    }

    requestPasswordReset(email) {
        return new Promise((resolve, reject) => {
            fetch('/request-password-reset', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email })
            }).then(response => {
                if (response.status === 200) this.logout()
                response.json().then(data => {
                    if (response.status >= 300) reject(data.message);
                    else resolve(data);
                }).catch(reject);
            }).catch(reject);
        })
    }
}
