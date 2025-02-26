// Authentication configuration
module.exports = {
    jwtSecret: process.env.JWT_SECRET || 'your_jwt_secret_key',
    jwtExpiration: '1h',
    saltRounds: 10
  };