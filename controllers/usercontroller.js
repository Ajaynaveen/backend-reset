const User = require('../models/user');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sendPasswordResetEmail = require('../sendPasswordResetEmail');

const SECRET_KEY = "forgetresetpassword";

const createuser = async (req, res) => {
  try {
    const { fname, email, password, cpassword } = req.body;

    const existinguser = await User.findOne({ email });

    if (existinguser) {
      return res.status(404).json({ message: 'Email already registered' });
    }

    if (password !== cpassword) {
      return res.status(501).send('Passwords do not match!');
    }

    const newuser = new User({
      fname,
      email: email.toLowerCase(),
      password,
      cpassword
    });

    await newuser.save();

    res.json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const loginuser = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(422).json({ message: 'Invalid Credentials' });
    }

    console.log('Hashed Password from Database:', user.password);
    console.log('Entered Password:', password);

    const matchpassword = await bcrypt.compare(password, user.password);
    console.log(matchpassword);

    if (!matchpassword) {
      return res.status(422).json({ message: 'Invalid password' });
    }

    const token = jwt.sign(
      { userId: user._id, fname: user.fname, email: user.email },
      SECRET_KEY,
      { expiresIn: '1hr' }
    );

    res.json(token);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};


const userprofile = async (req, res) => {
  try {
    const userId = req.userId;
    const user = await User.findById(userId, 'fname email');
    res.json(user);
  } catch (error) {
    console.error('error fetching user profile', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const forgetpassword = async (req, res) => {
  const { email } = req.body;
  console.log(email)

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const resetToken = jwt.sign({ email }, SECRET_KEY, { expiresIn: '1h' });

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

    await user.save();

    sendPasswordResetEmail(email, resetToken);

    res.json(resetToken);
  } catch (error) {
    console.error('Error sending password reset email:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const resetpassword = async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

module.exports = { createuser, loginuser, userprofile, forgetpassword, resetpassword };
