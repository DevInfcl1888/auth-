import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import jwt, { SignOptions } from 'jsonwebtoken';
import pool from '../db';
import { hashPassword, generateSalt } from '../utils/crypto.util';

const generateMDR_ID = () => `MDR-${Math.random().toString(36).substr(2, 9)}`;

// import jwt, { SignOptions } from 'jsonwebtoken';

const generateToken = (userId: string, secret: string, expiresIn: SignOptions["expiresIn"]): string => {
  const payload = { userId };
  const options: SignOptions = { expiresIn };
  return jwt.sign(payload, secret, options);
};

import crypto from 'crypto';

// export const register = async (req: Request, res: Response): Promise<void> => {
//   const {
//     first_name,
//     middle_name,
//     last_name,
//     password,
//     email,
//     phone_num,
//     dob,
//     gender,
//     image_url,
//     google_id,
//     blood_group,
//     city,
//     state,
//     country,
//     zip_code,
//     emergency_contact,
//     emergency_contact_name,
//     relationship,
//     referral_by,
//     referral_code,
//   } = req.body;

//   // Basic validation
//   if (!email || !password || !gender || !first_name || !last_name) {
//     res.status(400).json({ error: 'Missing required fields' });
//     return;
//   }

//   const salt = crypto.randomBytes(16).toString('hex');
//   const hashedPassword = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');

//   const id = uuidv4();
//   let mdr_id = generateMDR_ID();

//   try {
//     // Ensure unique mdr_id
//     while (true) {
//       const check = await pool.query('SELECT 1 FROM users WHERE mdr_id = $1', [mdr_id]);
//       if (check.rows.length === 0) break;
//       mdr_id = generateMDR_ID();
//     }

//     await pool.query(
//       `INSERT INTO users (
//         id, first_name, middle_name, last_name, password, salt, email, phone_num, dob, gender,
//         image_url, google_id, blood_group, city, state, country, zip_code,
//         emergency_contact, emergency_contact_name, relationship, referral_by, referral_code, mdr_id
//       ) VALUES (
//         $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
//         $11, $12, $13, $14, $15, $16, $17,
//         $18, $19, $20, $21, $22, $23
//       )`,
//       [
//         id,
//         first_name,
//         middle_name || null,
//         last_name,
//         hashedPassword,
//         salt,
//         email,
//         phone_num || null,
//         dob || null,
//         gender,
//         image_url || null,
//         google_id || null,
//         blood_group || null,
//         city || null,
//         state || null,
//         country || null,
//         zip_code || null,
//         emergency_contact || null,
//         emergency_contact_name || null,
//         relationship || null,
//         referral_by || null,
//         referral_code || null,
//         mdr_id
//       ]
//     );

//     res.status(201).json({ message: 'User registered', mdr_id });
//   } catch (err) {
//     res.status(500).json({ error: 'Registration failed', detail: err });
//   }
// };


export const register = async (req: Request, res: Response): Promise<void> => {
  const {
    first_name,
    middle_name,
    last_name,
    password,
    email,
    phone_num,
    dob,
    gender,
    image_url,
    google_id,
    blood_group,
    city,
    state,
    country,
    zip_code,
    emergency_contact,
    emergency_contact_name,
    relationship,
    referral_by,
    referral_code,
  } = req.body;

  // Basic validation
  if (!email || !password || !gender || !first_name || !last_name) {
    res.status(400).json({ error: 'Missing required fields' });
    return;
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const hashedPassword = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  const combinedPassword = `${salt}:${hashedPassword}`;

  const id = uuidv4();

  try {
    await pool.query(
        `INSERT INTO users (
          id, first_name, middle_name, last_name, password, email, phone_num, dob, gender,
          image_url, google_id, blood_group, city, state, country, zip_code,
          emergency_contact, emergency_contact_name, relationship, referral_by, referral_code
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
          $11, $12, $13, $14, $15, $16, $17,
          $18, $19, $20, $21
        )`,
        [
          id,
          first_name,
          middle_name || null,
          last_name,
          combinedPassword,
          email,
          phone_num || null,
          dob || null,
          gender,
          image_url || null,
          google_id || null,
          blood_group || null,
          city || null,
          state || null,
          country || null,
          zip_code || null,
          emergency_contact || null,
          emergency_contact_name || null,
          relationship || null,
          referral_by || null,
          referral_code || null,
        ]
      );
      

    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed', detail: (err as Error).message });
  }
};

// export const login = async (req: Request, res: Response): Promise<void> => {
//     const { email, password } = req.body;

//   try {
//     const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//     const user = result.rows[0];

//     if (!user) res.status(401).json({ error: 'Invalid email' });

//     const encryptedPw = hashPassword(password, ''); // NOTE: no salt stored = insecure!
//     if (encryptedPw !== user.password) res.status(401).json({ error: 'Invalid password' });

//     const accessToken = generateToken(user.id, process.env.ACCESS_TOKEN_SECRET!, '15m');
//     const refreshToken = generateToken(user.id, process.env.REFRESH_TOKEN_SECRET!, '7d');

//     res.json({ accessToken, refreshToken });
//   } catch (err) {
//     res.status(500).json({ error: 'Login failed' });
//   }
// };


// import crypto from 'crypto';

export const login = async (req: Request, res: Response): Promise<void> => {
    const { email, password } = req.body;
  
    try {
      const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
      const user = result.rows[0];
  
      if (!user) {
        res.status(401).json({ error: 'Invalid email' });
        return;
      }
  
      // Password is stored in the format "salt:hashedPassword"
      const [storedSalt, storedHash] = user.password.split(':');
      const computedHash = crypto
        .pbkdf2Sync(password, storedSalt, 1000, 64, 'sha512')
        .toString('hex');
  
      if (computedHash !== storedHash) {
        res.status(401).json({ error: 'Invalid password' });
        return;
      }
  
      const accessToken = generateToken(user.id, process.env.ACCESS_TOKEN_SECRET!, '15m');
      const refreshToken = generateToken(user.id, process.env.REFRESH_TOKEN_SECRET!, '7d');
  
      res.json({ accessToken, refreshToken });
    } catch (err) {
      res.status(500).json({ error: 'Login failed', detail: (err as Error).message });
    }
  };
  

export const logout = (_req: Request, res: Response) => {
  res.json({ message: 'Logged out (client should delete token)' });
};

export const resetPassword = async (req: Request, res: Response) => {
  const { email, newPassword } = req.body;

  try {
    const salt = generateSalt();
    const encryptedPw = hashPassword(newPassword, salt);

    await pool.query('UPDATE users SET password = $1 WHERE email = $2', [encryptedPw, email]);
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ error: 'Reset failed' });
  }
};

export const getProfile = async (req: Request, res: Response): Promise<void> => {
    const userId = (req as any).userId;

  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
};
