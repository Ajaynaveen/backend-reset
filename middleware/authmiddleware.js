const jwt=require('jsonwebtoken');
const authmiddleware = {
    verifytoken: (req, res, next) => {
      const token = req.headers.authorization;
      if (!token) {
        return res.status(401).json({ message: 'Authentication failed: Token missing' });
      }
      try {
        jwt.verify(token, 'forgetresetpassword', (err, decodedtoken) => {
          if (err) {
            if (err.name === 'TokenExpiredError') {
              return res.status(401).json({ message: 'Token expired' });
            } else {
              return res.status(401).json({ message: 'Authentication failed' });
            }
          }
          // Store the user ID in the request for later use
          req.userId = decodedtoken.userId;
          next();
        });
      } catch (error) {
        return res.status(500).json({ message: 'Internal server error' });
      }
    },
  };
  
  
  
  module.exports = authmiddleware;
  