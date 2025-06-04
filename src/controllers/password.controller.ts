import { Request, Response } from 'express';
import crypto from 'crypto';
import pool from '../db';
import { generateSalt, hashPassword } from '../utils/crypto.util';

const passwordResetTokens: Record<string, string> = {}; // In-memory token store

export const forgotPassword = async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (userResult.rowCount === 0) return res.status(404).json({ error: 'Email not registered' });

  const token = crypto.randomBytes(32).toString('hex');
  passwordResetTokens[email] = token;

  const resetUrl = `http://localhost:3000/api/password/reset-password?token=${token}&email=${email}`;
  console.log(`🔐 Reset Link: ${resetUrl}`);

  res.json({ message: 'Password reset link generated (check console)' });
};

export const resetPassword = async (req: Request, res: Response) => {
  const { email, token, newPassword } = req.body;

  if (!email || !token || !newPassword) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (passwordResetTokens[email] !== token) {
    return res.status(400).json({ error: 'Invalid or expired token' });
  }

  const salt = generateSalt();
  const encryptedPw = hashPassword(newPassword, salt);

  try {
    await pool.query(
      'UPDATE users SET password = $1, salt = $2 WHERE email = $3',
      [encryptedPw, salt, email]
    );

    delete passwordResetTokens[email];
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ error: 'Password reset failed' });
  }
};
