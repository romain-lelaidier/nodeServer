const express = require('express');
const dotenv = require('dotenv');
const { Sequelize } = require('sequelize');
const path = require('path');
const cookieParser = require('cookie-parser');
const generateRouter = require('./routes/authRoutes');

dotenv.config();
console.log(process.env)

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cookieParser());

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
const sequelize = new Sequelize(process.env.DATABASE_URL, {
    dialect: 'mysql',
    logging: false
});

sequelize.authenticate()
    .then(() => console.log('MySQL connected'))
    .catch(err => console.error('MySQL connection error:', err));

// Routes
const router = generateRouter(sequelize)
app.use(router);

// Redirect to homepage
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
