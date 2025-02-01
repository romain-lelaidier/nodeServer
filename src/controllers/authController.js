const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { Op } = require('sequelize');

class AuthController {
    constructor(userModel, jwt, bcrypt) {
        this.userModel = userModel;
        this.jwt = jwt;
        this.bcrypt = bcrypt;

        // this.transporter = nodemailer.createTransport({
        //     service: 'gmail',
        //     auth: {
        //         user: process.env.EMAIL_USER,
        //         pass: process.env.EMAIL_PASS
        //     }
        // });

        this.register = this.register.bind(this);
        this.verify = this.verify.bind(this);
        this.login = this.login.bind(this);
        this.refreshToken = this.refreshToken.bind(this);
        this.loadUser = this.loadUser.bind(this);
        this.requestPasswordReset = this.requestPasswordReset.bind(this);
        this.resetPassword = this.resetPassword.bind(this);
        this.updateEmail = this.updateEmail.bind(this);
        this.updatePassword = this.updatePassword.bind(this);
        this.removeAccount = this.removeAccount.bind(this);
    }

    async register(req, res) {
        const { username, password, email } = req.body;

        try {
            const userWithUsername = await this.userModel.findOne({ where: { username } });
            if (userWithUsername) {
                res.status(403).json({ message: "Sorry, this username is already taken" });
                return;
            }
            const userWithEmail = await this.userModel.findOne({ where: { email } });
            if (userWithEmail) {
                res.status(403).json({ message: "Sorry, this email is already taken" });
                return;
            }

            const newUser = await this.userModel.create({ username, password, email, isVerified: false });
            const verificationToken = crypto.randomBytes(32).toString('hex');
            const verificationLink = `${process.env.BASE_URL}/verify.html?token=${verificationToken}`;

            // Save the verification token to the user record
            newUser.verificationToken = verificationToken;
            await newUser.save();

            // Send verification email
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: newUser.email,
                subject: 'Account Verification',
                text: `Please verify your account by clicking the following link: ${verificationLink} `
            };

            // await this.transporter.sendMail(mailOptions);
            console.log(mailOptions);

            res.status(201).json({ message: 'User registered successfully. Please check your email to verify your account.' });
        } catch (error) {
            console.log(error)
            res.status(500).json({ message: 'Error registering user', error });
        }
    }

    loguser(user, res) {
        const accessToken  = this.jwt.sign({ id: user.id }, process.env.JWT_ACCESS_SECRET,  { expiresIn: '600s' });
        const refreshToken = this.jwt.sign({ id: user.id }, process.env.JWT_REFRESH_SECRET, { expiresIn: '1d' });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            sameSite: 'strict', secure: true,
            maxAge: 24 * 60 * 60 * 1000
        });

        res.status(200).json({
            message: 'Login successful', 
            username: user.username, 
            email: user.email,
            accessToken 
        });
    }

    async verify(req, res, next) {
        const { token } = req.params;

        try {
            const user = await this.userModel.findOne({ where: { verificationToken: token } });
            if (!user) {
                return res.status(400).json({ message: 'Invalid verification token' });
            }

            user.isVerified = true;
            user.verificationToken = null;
            await user.save();
            // this.loguser(user, res);
            res.status(200).json({ message: "Verification succesful", username: user.username })
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: 'Error verifying account', error });
        }
    }

    async login(req, res, next) {
        const { username, password } = req.body;

        try {
            const user = await this.userModel.findOne({ where: { [Op.or]: { username, email: username } } });
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            const isMatch = await user.comparePassword(password);
            if (!isMatch) {
                res.status(401).json({ message: 'Invalid credentials' });
                return next();
            }

            if (!user.isVerified) {
                res.status(401).json({ message: 'User not verified' });
                return next();
            }

            this.loguser(user, res);
            next();
        } catch (error) {
            res.status(500).json({ message: 'Error logging in', error });
        }
    }

    async refreshToken(req, res) {
        const refreshToken = req.cookies.refreshToken;
        const username = req.body.username;

        if (!refreshToken) {
            return res.status(403).json({ message: 'No refresh token provided!' });
        }

        try {
            this.jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, async (err, decoded) => {
                if (err) {
                    return res.status(401).json({ message: 'Unauthorized!' });
                }

                const user = await this.userModel.findOne({ where: { username } });
                const accessToken = this.jwt.sign({ id: user.id }, process.env.JWT_ACCESS_SECRET, { expiresIn: '600s' });
                res.status(200).json({ message: 'Token refreshed', accessToken });
            });
        } catch (error) {
            console.log(error)
            res.status(401).json({ message: 'Unauthorized!' });
        }
    }

    async loadUser(req, res, next) {
        const username = req.body.username || req.params.username;

        try {
            const user = await this.userModel.findOne({ where: { username } });
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            if (!user.isVerified) {
                res.status(401).json({ message: 'User not verified' });
                return next();
            }

            req.user = user;
            next();
        } catch (error) {
            console.log(error)
            res.status(500).json({ message: 'Error loading user', error });
        }
    }

    async requestPasswordReset(req, res, next) {
        const { email } = req.body;

        try {
            const user = await this.userModel.findOne({ where: { email } });
            if (!user) {
                return res.status(404).json({ message: 'Sorry, no account is associated to this email.' });
            }

            if (!user.isVerified) {
                res.status(401).json({ message: 'User not verified' });
                return next();
            }

            const now = Date.now();

            if (now < user.resetTokenExpiry) {
                res.status(403).json({ message: 'A password request link has already been sent to this address' })
                return next();
            }

            const resetToken = crypto.randomBytes(32).toString('hex');
            const resetLink = `${process.env.BASE_URL}/reset-password.html?token=${resetToken}`;

            // Save the reset token to the user record
            user.resetToken = resetToken;
            user.resetTokenExpiry = now + 3600*1000; // 1h
            await user.save();

            // Send password reset email
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: user.email,
                subject: 'Password Reset',
                text: `Please reset your password by clicking the following link: ${resetLink}. The link will be valid for an hour.`
            };

            // await this.transporter.sendMail(mailOptions);

            console.log(mailOptions)

            res.status(200).json({ message: 'Password reset email sent' });
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: 'Error requesting password reset', error });
        }
    }

    async resetPassword(req, res) {
        const { token, newPassword } = req.body;

        try {
            const user = await this.userModel.findOne({ where: { resetToken: token, resetTokenExpiry: { [Op.gt]: Date.now() } } });
            if (!user) {
                return res.status(400).json({ message: 'Invalid or expired reset token' });
            }

            user.password = await this.bcrypt.hash(newPassword, 10);
            user.resetToken = null;
            user.resetTokenExpiry = null;
            await user.save();

            res.status(200).json({ message: 'Password reset successfully' });
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: 'Error resetting password', error });
        }
    }

    async updateEmail(req, res) {
        const { newEmail } = req.body;
        const userId = req.user.id;

        try {
            const user = await this.userModel.findByPk(userId);
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            const userWithEmail = await this.userModel.findOne({ where: { email: newEmail } });
            if (userWithEmail) {
                return res.status(403).json({ message: 'Sorry, this email is already taken'})
            }

            user.email = newEmail;
            await user.save();

            res.status(200).json({ message: 'Email updated successfully' });
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: 'Error updating email', error });
        }
    }

    async updatePassword(req, res) {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user.id;

        try {
            const user = await this.userModel.findByPk(userId);
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            const isMatch = await user.comparePassword(currentPassword);
            if (!isMatch) {
                return res.status(401).json({ message: 'Invalid current password' });
            }

            user.password = await this.bcrypt.hash(newPassword, 10);
            await user.save();

            res.status(200).json({ message: 'Password updated successfully' });
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: 'Error updating password', error });
        }
    }

    async removeAccount(req, res) {
        const { password } = req.body;
        const userId = req.user.id;

        try {
            const user = await this.userModel.findByPk(userId);
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }

            const isMatch = await user.comparePassword(password);
            if (!isMatch) {
                return res.status(401).json({ message: 'Invalid password' });
            }

            await user.destroy();
            res.status(200).json({ message: 'Account removed successfully' });
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: 'Error removing account', error });
        }
    }
}

module.exports = AuthController;