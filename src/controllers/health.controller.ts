// controllers/health.controller.ts
import { Request, Response } from 'express';
import pool  from '../db';

export const healthCheck = async (req: Request, res: Response) => {
  try {
    // Optional: check database connectivity
    await pool.query('SELECT 1');

    res.status(200).json({ status: 'ok' });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({ status: 'error', message: 'Health check failed' });
  }
};
