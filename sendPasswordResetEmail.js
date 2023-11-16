const nodemailer = require('nodemailer');

// Configure the email transport
const transporter = nodemailer.createTransport({
  service: 'Gmail', // e.g., Gmail, Outlook, etc.
  auth: {
    user: 'ajay.s.naviee@gmail.com', // Your Gmail email address
    pass: 'zvxw gwsh thbt htlc', // Your Gmail password
  },
});

// Function to send a password reset email
const sendPasswordResetEmail = (toEmail, resetToken) => {
  const mailOptions = {
    from: 'ajay.s.naviee@gmail.com', // Your Gmail email address
    to: toEmail, // Recipient's email address
    subject: 'Password Reset',
    html: `<p>Click the following link to reset your password: <a href="http://localhost:3000/reset-password/${resetToken}">Reset Password</a></p>`,
  };


  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email:', error);
    } else {
      console.log('Email sent:', info.response);
    }
  });
};

module.exports = sendPasswordResetEmail;
