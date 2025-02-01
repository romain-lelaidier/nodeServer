const { encrypt, decrypt } = require('../utils/cryptoUtils')
const sequelize = require('sequelize')

class GameResultController {
    constructor(gameResultModel, userModel) {
        this.gameResultModel = gameResultModel;
        this.userModel = userModel;

        this.saveResult = this.saveResult.bind(this);
        this.getResults = this.getResults.bind(this);
        this.getLeaderboards = this.getLeaderboards.bind(this);
    }

    async saveResult(req, res, next) {
        const { score, gameType } = JSON.parse(decrypt(req.body.username, req.body.game));

        const userId = req.user.id;

        try {
            const newResult = await this.gameResultModel.create({ userId, score, gameType });
            res.status(201).json({ message: 'Game result saved successfully', result: newResult });
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: 'Error saving game result', error });
        }
    }

    async getResults(req, res, next) {
        const userId = req.user.id;

        try {
            const results = await this.gameResultModel.findAll({ where: { userId } });
            res.status(200).json({ results });
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: 'Error fetching game results', error });
        }
    }

    async getLeaderboards(req, res, next) {
        try {
            const leaderboards = await this.gameResultModel.findAll({
                attributes: ['userId', [sequelize.fn('MAX', sequelize.col('score')), 'score'], 'gameType'],
                group: ['userId', 'gameType'],
                order: [[sequelize.fn('MAX', sequelize.col('score')), 'DESC']],
                include: [{ model: this.userModel, attributes: ['username'] }],
                limit: 10
            });

            const formattedLeaderboards = leaderboards.map(entry => ({
                username: entry.User.username,
                score: entry.score,
                gameType: entry.gameType
            }));

            res.status(200).json({ leaderboards: formattedLeaderboards });
        } catch (error) {
            console.log(error);
            res.status(500).json({ message: 'Error fetching leaderboard', error });
        }
    }
}

module.exports = GameResultController;