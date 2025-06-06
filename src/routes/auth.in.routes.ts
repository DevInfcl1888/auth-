import express from 'express';
import { register, loginWemail, logout, resetPassword, getProfile, refreshToken } from '../controllers/auth.controller';
import { healthCheck  } from '../controllers/health.controller';
import { authenticateToken } from '../middlewares/auth.middleware';

const router = express.Router();

router.post('/register', register);
router.get('/health', healthCheck);
router.post('/login', loginWemail);
router.post('/logout', logout);
router.post('/reset-password', resetPassword);
router.post('/refresh', refreshToken);
router.get('/profile', authenticateToken, getProfile);

export default router;
