import { Router } from 'express';
import { forgotPassword, resetPassword } from '../controllers/password.controller';

const router = Router();

router.post('/forgot-password', forgotPassword as any);
router.post('/reset-password', resetPassword as any);

export default router;
