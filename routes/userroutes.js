const express = require('express');
const router = express.Router();
const authmiddleware=require('../middleware/authmiddleware')

const {createuser}=require('../controllers/usercontroller');
const {loginuser}=require('../controllers/usercontroller')
const {userprofile}=require('../controllers/usercontroller')
const {forgetpassword}=require('../controllers/usercontroller')
const {resetpassword}=require('../controllers/usercontroller')
router.post('/users', createuser);
router.post('/login',loginuser)
router.post('/forgetpassword',forgetpassword)
router.post('/reset-password/:token',resetpassword)
router.get('/profile',authmiddleware.verifytoken,userprofile)

module.exports = router;