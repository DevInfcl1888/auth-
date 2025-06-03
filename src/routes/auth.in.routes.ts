import express from 'express';
import { register, login, logout, resetPassword, getProfile, refreshToken } from '../controllers/auth.controller';
import { authenticateToken } from '../middlewares/auth.middleware';

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);
router.post('/reset-password', resetPassword);
router.post('/refresh', refreshToken);
router.get('/profile', authenticateToken, getProfile);

export default router;
