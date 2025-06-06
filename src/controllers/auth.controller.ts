import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import jwt, { SignOptions, JwtPayload  } from 'jsonwebtoken';
import pool from '../db';
import { hashPassword, generateSalt } from '../utils/crypto.util';
import { redisClient } from '../redisClient'; // Your initialized Redis client
import { generateTokens } from '../utils/jwt'; // your token generation utility


const generateMDR_ID = () => `MDR-${Math.random().toString(36).substr(2, 9)}`;

// import jwt, { SignOptions } from 'jsonwebtoken';

// const generateToken = (userId: string, secret: string, expiresIn: SignOptions["expiresIn"]): string => {
//   const payload = { userId };
//   const options: SignOptions = { expiresIn };
//   return jwt.sign(payload, secret, options);
// };
const generateToken = (
  userId: string,
  sessionId: string,
  secret: string,
  expiresIn: string
): string => {
  const payload = { userId, sessionId };
  const options: SignOptions = { expiresIn: expiresIn as any  };
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

//   const lowerCaseEmail = email.toLowerCase();
//   const salt = crypto.randomBytes(16).toString('hex');
//   const hashedPassword = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
//   const combinedPassword = `${salt}:${hashedPassword}`;
//   const id = uuidv4();

//   try {
//     await pool.query(
//       `INSERT INTO users (
//         id, first_name, middle_name, last_name, password, email, phone_num, dob, gender,
//         image_url, google_id, blood_group, city, state, country, zip_code,
//         emergency_contact, emergency_contact_name, relationship, referral_by, referral_code
//       ) VALUES (
//         $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
//         $11, $12, $13, $14, $15, $16, $17,
//         $18, $19, $20, $21
//       )`,
//       [
//         id,
//         first_name,
//         middle_name || null,
//         last_name,
//         combinedPassword,
//         lowerCaseEmail,
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
//       ]
//     );

//     // Fetch mdr_id using the inserted user's id
//     const result = await pool.query('SELECT mdr_id FROM users WHERE id = $1', [id]);
//     const mdr_id = result.rows[0]?.mdr_id;

//     res.status(201).json({ message: 'User registered', mdr_id, id });
//   } catch (err: any) {
//     const detail = err.message || '';
//     if (detail.includes('duplicate key value') && detail.includes('"email_unique"')) {
//       res.status(409).json({ error: 'User already exists with the same email' });
//     } else if (detail.includes('duplicate key value') && detail.includes('"phone_num"')) {
//       res.status(409).json({ error: 'User already exists with the same phone number' });
//     } else {
//       res.status(500).json({ error: 'Registration failed', detail });
//     }
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

  if (!email || !password || !gender || !first_name || !last_name) {
    res.status(400).json({ error: 'Missing required fields' });
    return;
  }

  const lowerCaseEmail = email.toLowerCase();
  const salt = crypto.randomBytes(16).toString('hex');
  const hashedPassword = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  const combinedPassword = `${salt}:${hashedPassword}`;
  const id = uuidv4();

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    await client.query(
      `INSERT INTO users (
        id, first_name, middle_name, last_name, password, email, phone_num, dob, gender,
        image_url, google_id, blood_group, city, state, country, zip_code,
        emergency_contact, emergency_contact_name, relationship, referral_by
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
        $11, $12, $13, $14, $15, $16, $17,
        $18, $19, $20
      )`,
      [
        id,
        first_name,
        middle_name || null,
        last_name,
        combinedPassword,
        lowerCaseEmail,
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
      ]
    );

    const result = await client.query('SELECT mdr_id FROM users WHERE id = $1', [id]);
    const mdr_id = result.rows[0]?.mdr_id;

    let referralResult: any = null;

    if (referral_code) {
      // Fetch user mdr_id and referred user by referral_code
      const userRes = await client.query('SELECT id, mdr_id FROM users WHERE id = $1', [id]);
      const referrerRes = await client.query(
        'SELECT id, mdr_id FROM users WHERE referral_code = $1',
        [referral_code]
      );

      if (referrerRes.rowCount! > 0 && userRes.rowCount! > 0) {

        const user = userRes.rows[0];
        const referrer = referrerRes.rows[0];

        if (referrer.id !== user.id) {
          const date = new Date();

          await client.query(
            'UPDATE users SET referral_by = $1 WHERE id = $2',
            [referral_code, user.id]
          );

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
              referral_code,
              date,
            ]
          );

          await client.query(
            'UPDATE users SET referral_count = referral_count + 1 WHERE id = $1',
            [referrer.id]
          );

          await client.query(
            `INSERT INTO rewards (name, type, amount, user_id, statement, status, date)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            ['scratch card', 'OCR Credit', 3, referrer.id, '', true, date]
          );

          referralResult = {
            referral_by: referral_code,
            referral_date: date,
            referred_by: referrer.id,
            referred_by_mdr_id: referrer.mdr_id,
          };
        } else {
          referralResult = { error: 'User cannot refer themselves' };
        }
      } else {
        referralResult = { error: 'Invalid referral code' };
      }
    }

    await client.query('COMMIT');
    // Generate session and tokens
    const sessionId = uuidv4();
    const accessToken = generateToken(id, sessionId, process.env.ACCESS_TOKEN_SECRET!, '15m');
    const refreshToken = generateToken(id, sessionId, process.env.REFRESH_TOKEN_SECRET!, '7d');

    // Store refresh token in Redis
    const redisKey = `${SESSION_PREFIX}${id}:${sessionId}`;
    await redisClient.set(redisKey, refreshToken, { EX: 7 * 24 * 60 * 60 }); // 7 days


    res.status(201).json({
      message: 'User registered',
      id,
      mdr_id,
      accessToken,
      refreshToken,
      ...(referralResult ? { referral: referralResult } : {}),
    });
  } catch (err: any) {
    await client.query('ROLLBACK');
    const detail = err.message || '';
    if (detail.includes('duplicate key value') && detail.includes('"email_unique"')) {
      res.status(409).json({ error: 'User already exists with the same email' });
    } else if (detail.includes('duplicate key value') && detail.includes('"phone_num"')) {
      res.status(409).json({ error: 'User already exists with the same phone number' });
    } else {
      res.status(500).json({ error: 'Registration failed', detail });
    }
  } finally {
    client.release();
  }
};




const MAX_SESSIONS = 5;
const SESSION_PREFIX = 'user_session:'; // Redis key prefix for sessions


export const loginWphone = async (req: Request, res: Response): Promise<void> => {
  const { phone_num, password } = req.body;

  try {
    // 1. Fetch user by phone number
    const result = await pool.query('SELECT * FROM users WHERE phone_num = $1', [phone_num]);
    const user = result.rows[0];

    if (!user) {
      res.status(401).json({ error: 'Invalid phone number' });
      return;
    }

    // 2. Verify password
    const [storedSalt, storedHash] = user.password.split(':');
    const computedHash = crypto.pbkdf2Sync(password, storedSalt, 1000, 64, 'sha512').toString('hex');
    if (computedHash !== storedHash) {
      res.status(401).json({ error: 'Invalid password' });
      return;
    }

    // 3. Check active sessions in Redis
    const userSessionKeys = await redisClient.keys(`${SESSION_PREFIX}${user.id}:*`);
    const sessionCount = userSessionKeys.length;

    if (sessionCount >= MAX_SESSIONS) {
      res.status(403).json({ error: `Maximum active sessions reached (${MAX_SESSIONS})`, sessionCount });
      return;
    }

    // 4. Generate session ID and tokens
    const sessionId = uuidv4();
    const accessToken = generateToken(user.id, sessionId, process.env.ACCESS_TOKEN_SECRET!, '15m');
    const refreshToken = generateToken(user.id, sessionId, process.env.REFRESH_TOKEN_SECRET!, '7d');

    // 5. Store session info in Redis
    const redisKey = `${SESSION_PREFIX}${user.id}:${sessionId}`;
    await redisClient.set(redisKey, refreshToken, { EX: 7 * 24 * 60 * 60 });

    // 6. Respond with tokens and session count
    res.json({
      accessToken,
      refreshToken,
      sessionCount: sessionCount + 1, // new session being added
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed', detail: (err as Error).message });
  }
};


const isValidEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

export const loginWemail = async (req: Request, res: Response): Promise<void> => {
  let { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ error: 'Email/MDR ID and password are required' });
    return;
  }

  let userQuery: string;
  let queryValue: string;

  if (isValidEmail(email)) {
    email = email.toLowerCase();
    userQuery = 'SELECT * FROM users WHERE email = $1';
    queryValue = email;
  } else if (/^mdr\d{10}[a-zA-Z]$/i.test(email)) {
    const mdrId = email.toUpperCase();
    userQuery = 'SELECT * FROM users WHERE mdr_id = $1';
    queryValue = mdrId;
  } else {
    res.status(400).json({ error: 'Invalid email or MDR ID format' });
    return;
  }

  try {
    const result = await pool.query(userQuery, [queryValue]);
    const user = result.rows[0];

    if (!user) {
      res.status(401).json({ error: 'Invalid email or MDR ID' });
      return;
    }

    const [storedSalt, storedHash] = user.password.split(':');
    const computedHash = crypto.pbkdf2Sync(password, storedSalt, 1000, 64, 'sha512').toString('hex');

    if (computedHash !== storedHash) {
      res.status(401).json({ error: 'Invalid password' });
      return;
    }

    // 3. Check active sessions in Redis
    const userSessionKeys = await redisClient.keys(`${SESSION_PREFIX}${user.id}:*`);
    const sessionCount = userSessionKeys.length;

    if (sessionCount >= MAX_SESSIONS) {
      res.status(403).json({ error: `Maximum active sessions reached (${MAX_SESSIONS})`, sessionCount });
      return;
    }

    const sessionId = uuidv4();
    const accessToken = generateToken(user.id, sessionId, process.env.ACCESS_TOKEN_SECRET!, '15m');
    const refreshToken = generateToken(user.id, sessionId, process.env.REFRESH_TOKEN_SECRET!, '7d');

    const redisKey = `${SESSION_PREFIX}${user.id}:${sessionId}`;
    await redisClient.set(redisKey, refreshToken, { EX: 7 * 24 * 60 * 60 });

    res.json({ accessToken, refreshToken,sessionCount: sessionCount + 1 });
  } catch (err) {
    res.status(500).json({ error: 'Login failed', detail: (err as Error).message });
  }
};

export const refreshToken = async (req: Request, res: Response): Promise<void> => {
  const token = req.body.refreshToken || req.cookies?.refreshToken;

  if (!token) {
    res.status(401).json({ error: 'Refresh token required' });
    return;
  }

  try {
    // Check blacklist
    const isBlacklisted = await redisClient.get(`bl_token:${token}`);
    if (isBlacklisted) {
      res.status(403).json({ error: 'Token is blacklisted' });
      return;
    }

    // Verify token & extract payload
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET!) as JwtPayload;
    const { userId, sessionId } = decoded;

    // Validate session exists in Redis
    const redisKey = `${SESSION_PREFIX}${userId}:${sessionId}`;
    const storedRefreshToken = await redisClient.get(redisKey);

    if (!storedRefreshToken || storedRefreshToken !== token) {
      res.status(403).json({ error: 'Invalid refresh token or session expired' });
      return;
    }

    // Generate new access token (no refresh token rotation here)
    const newAccessToken = generateToken(userId, sessionId, process.env.ACCESS_TOKEN_SECRET!, '15m');

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(403).json({ error: 'Invalid refresh token', detail: (err as Error).message });
  }
};

export const logout = async (req: Request, res: Response): Promise<void> => {
  const token = req.body.refreshToken || req.cookies?.refreshToken;

  if (!token) {
    res.status(400).json({ error: 'Refresh token is required' });
    return;
  }

  try {
    const decoded = jwt.decode(token) as JwtPayload;
  
    if (!decoded || typeof decoded.exp !== 'number' || !decoded.sessionId || !decoded.userId) {
      res.status(400).json({ error: 'Invalid refresh token' });
      return;
    }
  
    const ttl = Math.floor(decoded.exp - Date.now() / 1000);
  
    if (ttl > 0) {
      await redisClient.set(`bl_token:${token}`, '1', { EX: ttl });
    } else {
      // expired token: no need to set expiry or set minimal expiry
      await redisClient.set(`bl_token:${token}`, '1');
    }
  
    const accessToken = req.headers['authorization']?.split(' ')[1];
    if (accessToken) {
      const accessDecoded = jwt.decode(accessToken) as JwtPayload;
      if (accessDecoded?.exp) {
        const accessTtl = Math.floor(accessDecoded.exp - Date.now() / 1000);
        if (accessTtl > 0) {
          await redisClient.set(`bl_token:${accessToken}`, '1', { EX: accessTtl });
        } else {
          await redisClient.set(`bl_token:${accessToken}`, '1');
        }
      }
    }
  
    const redisKey = `${SESSION_PREFIX}${decoded.userId}:${decoded.sessionId}`;
    await redisClient.del(redisKey);
  
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Logout failed', detail: (err as Error).message });
  }
  
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

export const resetAllSessions = async (req: Request, res: Response): Promise<void> => {
  const { userId } = req.body;

  if (!userId) {
    res.status(400).json({ error: 'userId is required' });
    return;
  }

  try {
    // Get all session keys for the user
    const keys = await redisClient.keys(`${SESSION_PREFIX}${userId}:*`);

    if (keys.length === 0) {
      res.json({ message: 'No active sessions found for this user' });
      return;
    }

    // Optionally blacklist all tokens (if implementing token blacklist)
    for (const key of keys) {
      const token = await redisClient.get(key);
      if (token) {
        await redisClient.set(`bl_token:${token}`, 'true', { EX: 7 * 24 * 60 * 60 });
      }
    }

    // Delete all sessions
    await redisClient.del(keys);

    res.json({ message: 'All sessions reset', count: keys.length });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset sessions', detail: (err as Error).message });
  }
};

