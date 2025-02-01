const { Sequelize, DataTypes, Model } = require('sequelize');
const { User } = require("./userModel")

function generateGameResultModel(sequelize) {

    class GameResult extends Model {}
    
    const gameResult = GameResult.init({
        userId: {
            type: DataTypes.INTEGER,
            allowNull: false,
            references: {
                model: User,
                key: 'id'
            }
        },
        score: {
            type: DataTypes.INTEGER,
            allowNull: false
        },
        gameType: {
            type: DataTypes.INTEGER,
            allowNull: false
        },
        date: {
            type: DataTypes.DATE,
            defaultValue: DataTypes.NOW
        }
    }, {
        sequelize,
        modelName: 'GameResult'
    });

    // Define associations
    User.hasMany(GameResult, { foreignKey: 'userId' });
    GameResult.belongsTo(User, { foreignKey: 'userId' });

    sequelize.sync();
    
    return gameResult;

};

module.exports = {
    generateGameResultModel
}