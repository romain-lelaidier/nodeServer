const express = require('express');
const AuthController = require('../controllers/authController');
const GameResultController = require('../controllers/gameResultController');
const { generateUserModel } = require('../models/userModel');
const { generateGameResultModel } = require('../models/gameResultModel');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authenticateToken = require('../middleware/authMiddleware');

module.exports = function generateRouter(sequelize) {
    const router = express.Router();

    const userModel = generateUserModel(bcrypt, sequelize);
    const authController = new AuthController(userModel, jwt, bcrypt);
    const gameResultModel = generateGameResultModel(sequelize);
    const gameResultController = new GameResultController(gameResultModel, userModel);

    router.post('/register', authController.register);
    router.get('/verify/:token', authController.verify);
    router.post('/login', authController.login);
    router.post('/refresh-token', authController.refreshToken);
    router.post('/save-result', authenticateToken, authController.loadUser, gameResultController.saveResult);
    router.get('/personal-results/:username', authenticateToken, authController.loadUser, gameResultController.getResults);
    router.post('/request-password-reset', authController.requestPasswordReset);
    router.post('/reset-password', authController.resetPassword);
    router.post('/update-email', authenticateToken, authController.loadUser, authController.updateEmail);
    router.post('/update-password', authenticateToken, authController.loadUser, authController.updatePassword);
    router.post('/remove-account', authenticateToken, authController.loadUser, authController.removeAccount);
    router.get('/leaderboards', gameResultController.getLeaderboards);

    return router;
}