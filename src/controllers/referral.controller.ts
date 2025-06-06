import { Request, Response } from 'express';
import pool from '../db'; // adjust path as needed
import { v4 as uuidv4 } from 'uuid';

// export const addReferral = async (req: Request, res: Response): Promise<void> => {
//   const { userId, referral_by } = req.body;

//   if (!userId || !referral_by) {
//     res.status(400).json({ error: 'userId and referral_by are required' });
//     return;
//   }

//   const client = await pool.connect();

//   try {
//     await client.query('BEGIN');

//     // Step 1: Fetch user
//     const userRes = await client.query(
//       'SELECT id, referral_by FROM users WHERE id = $1',
//       [userId]
//     );

//     if (userRes.rowCount === 0) {
//       await client.query('ROLLBACK');
//       res.status(404).json({ error: 'User not found' });
//       return;
//     }

//     const user = userRes.rows[0];

//     // Step 2: Prevent already referred user
//     if (user.referral_by) {
//       await client.query('ROLLBACK');
//       res.status(400).json({ error: 'User is already referred and cannot change referral' });
//       return;
//     }

//     // Step 3: Validate referral_by (must exist as referral_code)
//     const referrerRes = await client.query(
//       'SELECT id FROM users WHERE referral_code = $1',
//       [referral_by]
//     );

//     if (referrerRes.rowCount === 0) {
//       await client.query('ROLLBACK');
//       res.status(404).json({ error: 'Invalid referral code' });
//       return;
//     }

//     const referrer = referrerRes.rows[0];

//     // Step 4: Prevent self-referral
//     if (referrer.id === user.id) {
//       await client.query('ROLLBACK');
//       res.status(400).json({ error: 'You cannot refer yourself' });
//       return;
//     }

//     const date = new Date();

//     // Step 5: Update user with referral_by
//     await client.query(
//       'UPDATE users SET referral_by = $1 WHERE id = $2',
//       [referral_by, userId]
//     );

//     // Step 6: Log the referral
//     await client.query(
//       `INSERT INTO referrals (id, user_id, referred_by, referral_code, referral_date)
//        VALUES ($1, $2, $3, $4, $5)`,
//       [uuidv4(), userId, referrer.id, referral_by, date]
//     );

//     // Step 7: Increment referral count
//     await client.query(
//       'UPDATE users SET referral_count = referral_count + 1 WHERE id = $1',
//       [referrer.id]
//     );

//     // Step 8: Insert reward for referrer
//     await client.query(
//       `INSERT INTO rewards (name, type, amount, user_id, statement, status, date)
//        VALUES ($1, $2, $3, $4, $5, $6, $7)`,
//       ['scratch card', 'OCR Credit', 3, referrer.id, '', true, date]
//     );

//     await client.query('COMMIT');

//     res.status(200).json({
//       message: 'Referral added successfully',
//       referral_by,
//       referral_date: date,
//     });
//   } catch (err) {
//     await client.query('ROLLBACK');
//     console.error(err);
//     res.status(500).json({ error: 'Internal Server Error' });
//   } finally {
//     client.release();
//   }
// };
export const addReferral = async (req: Request, res: Response): Promise<void> => {
    const { userId, referral_by } = req.body;
  
    if (!userId || !referral_by) {
      res.status(400).json({ error: 'userId and referral_by are required' });
      return;
    }
  
    const client = await pool.connect();
  
    try {
      await client.query('BEGIN');
  
      // Step 1: Get user info
      const userRes = await client.query(
        'SELECT id, referral_by, mdr_id FROM users WHERE id = $1',
        [userId]
      );
  
      if (userRes.rowCount === 0) {
        await client.query('ROLLBACK');
        res.status(404).json({ error: 'User not found' });
        return;
      }
  
      const user = userRes.rows[0];
  
      if (user.referral_by) {
        await client.query('ROLLBACK');
        res.status(400).json({ error: 'User is already referred and cannot change referral' });
        return;
      }
  
      // Step 2: Get referrer info by referral_code
      const referrerRes = await client.query(
        'SELECT id, mdr_id FROM users WHERE referral_code = $1',
        [referral_by]
      );
  
      if (referrerRes.rowCount === 0) {
        await client.query('ROLLBACK');
        res.status(404).json({ error: 'Invalid referral code' });
        return;
      }
  
      const referrer = referrerRes.rows[0];
  
      if (referrer.id === user.id) {
        await client.query('ROLLBACK');
        res.status(400).json({ error: 'You cannot refer yourself' });
        return;
      }
  
      const date = new Date();
  
      // Step 3: Update referral_by in user record
      await client.query(
        'UPDATE users SET referral_by = $1 WHERE id = $2',
        [referral_by, userId]
      );
  
      // Step 4: Insert into referrals table with both userId and mdr_id
      await client.query(
        `INSERT INTO referrals (
          id, user_id, user_mdr_id, referred_by, referred_by_mdr_id, referral_code, referral_date
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7
        )`,
        [
          uuidv4(),
          user.id,
          user.mdr_id,
          referrer.id,
          referrer.mdr_id,
          referral_by,
          date
        ]
      );
  
      // Step 5: Increment referral count
      await client.query(
        'UPDATE users SET referral_count = referral_count + 1 WHERE id = $1',
        [referrer.id]
      );
  
      // Step 6: Insert reward
      await client.query(
        `INSERT INTO rewards (name, type, amount, user_id, statement, status, date)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        ['scratch card', 'OCR Credit', 3, referrer.id, '', true, date]
      );
  
      await client.query('COMMIT');
  
      res.status(200).json({
        message: 'Referral added successfully',
        referral_by,
        referral_date: date,
        user_id: user.id,
        user_mdr_id: user.mdr_id,
        referred_by: referrer.id,
        referred_by_mdr_id: referrer.mdr_id,
      });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error(err);
      res.status(500).json({ error: 'Internal Server Error' });
    } finally {
      client.release();
    }
  };
  