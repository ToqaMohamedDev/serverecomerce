const express = require('express');
const {
  signupValidator,
  loginValidator,
} = require('../utils/validators/authValidator');

const {
  signup,
  login,
  forgotPassword,
  verifyPassResetCode,
  resetPassword,
  getUserNext,
  uploadUserImage,
  resizeImage
} = require('../services/authService');

const router = express.Router();

router.post('/signup',  uploadUserImage,
  resizeImage, signupValidator, signup).get('/getMeNext',getUserNext);

router.post('/login', loginValidator, login);
router.post('/forgotPassword', forgotPassword);
router.post('/verifyResetCode', verifyPassResetCode);
router.put('/resetPassword', resetPassword);

module.exports = router;
