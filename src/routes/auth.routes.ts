import express from 'express';
import { register, loginWemail, logout, resetPassword, getProfile, refreshToken, loginWphone, resetAllSessions } from '../controllers/auth.controller';
import { authenticateToken } from '../middlewares/auth.middleware';
import { healthCheck  } from '../controllers/health.controller';
import { addReferral  } from '../controllers/referral.controller';

const router = express.Router();


router.post('/by/US', addReferral);

router.post('/register', register);
router.get('/health', healthCheck);
router.post('/reset', resetAllSessions);

router.post('/login', loginWemail);
router.post('/loginWphone', loginWphone);
router.post('/logout', logout);
router.post('/reset-password', resetPassword);
router.post('/refresh', refreshToken);
router.get('/profile', authenticateToken, getProfile);

export default router;
