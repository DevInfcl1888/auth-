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



export const register = async (req: Request, res: Response): Promise<void> => {
 let {
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

    email = email?.trim().toLowerCase();
    
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
//   const { email, password } = req.body;

//   try {
//     const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//     const user = result.rows[0];

//     if (!user) {
//       res.status(401).json({ error: 'Invalid email' });
//       return;
//     }

//     const [storedSalt, storedHash] = user.password.split(':');
//     const computedHash = crypto.pbkdf2Sync(password, storedSalt, 1000, 64, 'sha512').toString('hex');

//     if (computedHash !== storedHash) {
//       res.status(401).json({ error: 'Invalid password' });
//       return;
//     }

//     // Skip session counting since we're not saving sessions

//     const sessionId = uuidv4();
//     const accessToken = generateToken(user.id, sessionId, process.env.ACCESS_TOKEN_SECRET!, '15m');
//     const refreshToken = generateToken(user.id, sessionId, process.env.REFRESH_TOKEN_SECRET!, '7d');

//     // Do NOT save refreshToken or session in DB

//     res.json({ accessToken, refreshToken });
//   } catch (err) {
//     res.status(500).json({ error: 'Login failed', detail: (err as Error).message });
//   }
// };

// export const refreshToken = async (req: Request, res: Response): Promise<void> => {
//   const token = req.body.refreshToken || req.cookies?.refreshToken;

//   if (!token) {
//     res.status(401).json({ error: 'Refresh token required' });
//     return;
//   }

//   try {
//     // Check if token is blacklisted in Redis
//     const isBlacklisted = await redisClient.get(`bl_token:${token}`);
//     if (isBlacklisted) {
//       res.status(403).json({ error: 'Token is blacklisted' });
//       return;
//     }

//     // Verify refresh token signature & payload
//     const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET!) as JwtPayload;

//     if (!decoded.userId || !decoded.sessionId) {
//       res.status(403).json({ error: 'Invalid token payload' });
//       return;
//     }

//     // Generate new access token
//     const newAccessToken = generateToken(
//       decoded.userId,
//       decoded.sessionId,
//       process.env.ACCESS_TOKEN_SECRET!,
//       '15m'
//     );

//     res.json({ accessToken: newAccessToken });
//   } catch (err) {
//     res.status(403).json({ error: 'Invalid refresh token', detail: (err as Error).message });
//   }
// };

// export const logout = async (req: Request, res: Response): Promise<void> => {
//   const token = req.body.refreshToken || req.cookies?.refreshToken;

//   if (!token) {
//     res.status(400).json({ error: 'Refresh token is required' });
//     return;
//   }

//   try {
//     const decoded = jwt.decode(token) as JwtPayload;

//     if (
//       !decoded ||
//       typeof decoded.exp !== 'number' ||
//       !decoded.sessionId ||
//       !decoded.userId
//     ) {
//       res.status(400).json({ error: 'Invalid refresh token' });
//       return;
//     }

//     const ttl = decoded.exp - Math.floor(Date.now() / 1000);
//     if (ttl <= 0) {
//       res.status(400).json({ error: 'Token already expired' });
//       return;
//     }

//     // Blacklist refresh token with TTL (in seconds)
//     await redisClient.set(`bl_token:${token}`, '1', { EX: ttl });

//     // Blacklist access token as well (access token must be sent in Authorization header)
//     const authHeader = req.headers['authorization'];
//     if (authHeader) {
//       const accessToken = authHeader.split(' ')[1];
//       if (accessToken) {
//         const accessDecoded = jwt.decode(accessToken) as JwtPayload;
//         if (accessDecoded?.exp) {
//           const accessTtl = accessDecoded.exp - Math.floor(Date.now() / 1000);
//           if (accessTtl > 0) {
//             await redisClient.set(`bl_token:${accessToken}`, '1', { EX: accessTtl });
//           }
//         }
//       }
//     }

//     // If you want to remove session from Postgres, uncomment this
//     // await pool.query('DELETE FROM user_sessions WHERE user_id = $1 AND session_id = $2', [
//     //   decoded.userId,
//     //   decoded.sessionId,
//     // ]);

//     res.json({ message: 'Logged out successfully' });
//   } catch (err) {
//     res.status(500).json({ error: 'Logout failed', detail: (err as Error).message });
//   }
// };
// import { Request, Response } from 'express';
// import crypto from 'crypto';
// import jwt, { JwtPayload } from 'jsonwebtoken';
// import { v4 as uuidv4 } from 'uuid';
// import { pool } from './db'; // your postgres pool import
// import { redisClient } from './redis'; // your redis client import
// import { generateToken } from './auth'; // your token generator function

const MAX_SESSIONS = 5;
const SESSION_PREFIX = 'user_session:'; // Redis key prefix for sessions
const commonLogin = async (
  res: Response,
  identifierField: 'email' | 'phone_num' | 'mdr_id',
  identifierValue: string,
  password: string
): Promise<void> => {
  try {
    const query = `SELECT * FROM users WHERE ${identifierField} = $1`;
    const result = await pool.query(query, [identifierValue]);
    const user = result.rows[0];

    if (!user) {
      res.status(401).json({ error: `Invalid ${identifierField}` });
      return;
    }

    // ✅ Use correct salt & password (since they are stored in separate columns)
    const storedSalt = user.salt;
    const storedHash = user.password;
    const computedHash = crypto
      .pbkdf2Sync(password, storedSalt, 1000, 64, 'sha512')
      .toString('hex');

    if (computedHash !== storedHash) {
      res.status(401).json({ error: 'Invalid password' });
      return;
    }

    // ✅ Handle max session logic, JWT etc.
    const sessionKeys = await redisClient.keys(`${SESSION_PREFIX}${user.id}:*`);
    if (sessionKeys.length >= MAX_SESSIONS) {
      res.status(403).json({ error: `Max sessions (${MAX_SESSIONS}) reached` });
      return;
    }

    const sessionId = uuidv4();
    const accessToken = generateToken(user.id, sessionId, process.env.ACCESS_TOKEN_SECRET!, '15m');
    const refreshToken = generateToken(user.id, sessionId, process.env.REFRESH_TOKEN_SECRET!, '7d');
    const redisKey = `${SESSION_PREFIX}${user.id}:${sessionId}`;
    await redisClient.set(redisKey, refreshToken, { EX: 7 * 24 * 60 * 60 });

    res.json({ accessToken, refreshToken });
  } catch (err) {
    res.status(500).json({ error: 'Login failed', detail: (err as Error).message });
  }
};

export const loginWithEmail = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ error: 'Email & password required' });
    return; // ✅ add this
  }

  await commonLogin(res, 'email', email.toLowerCase(), password); // ✅ no need to return value
};

export const loginWithPhone = async (req: Request, res: Response): Promise<void> => {
  const { phone, password } = req.body;
  if (!phone || !password) {
    res.status(400).json({ error: 'Phone & password required' });
    return;
  }

  await commonLogin(res, 'phone_num', phone, password);
};

export const loginWithMdrId = async (req: Request, res: Response): Promise<void> => {
  const { mdr_id, password } = req.body;
  if (!mdr_id || !password) {
    res.status(400).json({ error: 'MDR ID & password required' });
    return;
  }

  await commonLogin(res, 'mdr_id', mdr_id, password);
};



// export const login = async (req: Request, res: Response): Promise<void> => {
//   const { email, password } = req.body;

//   try {
//     // 1. Fetch user from Postgres (password still stored there)
//     const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
//     const user = result.rows[0];

//     if (!user) {
//       res.status(401).json({ error: 'Invalid email' });
//       return;
//     }

//     // 2. Verify password with stored salt & hash
//     const [storedSalt, storedHash] = user.password.split(':');
//     const computedHash = crypto.pbkdf2Sync(password, storedSalt, 1000, 64, 'sha512').toString('hex');
//     if (computedHash !== storedHash) {
//       res.status(401).json({ error: 'Invalid password' });
//       return;
//     }

//     // 3. Check active sessions count in Redis
//     const userSessionKeys = await redisClient.keys(`${SESSION_PREFIX}${user.id}:*`);
//     if (userSessionKeys.length >= MAX_SESSIONS) {
//       res.status(403).json({ error: `Maximum active sessions reached (${MAX_SESSIONS})` });
//       return;
//     }

//     // 4. Create new sessionId, tokens
//     const sessionId = uuidv4();
//     const accessToken = generateToken(user.id, sessionId, process.env.ACCESS_TOKEN_SECRET!, '15m');
//     const refreshToken = generateToken(user.id, sessionId, process.env.REFRESH_TOKEN_SECRET!, '7d');

//     // 5. Store session info in Redis with TTL = 7 days (refresh token expiry)
//     const redisKey = `${SESSION_PREFIX}${user.id}:${sessionId}`;
//     await redisClient.set(redisKey, refreshToken, { EX: 7 * 24 * 60 * 60 });

//     // 6. Return tokens
//     res.json({ accessToken, refreshToken });
//   } catch (err) {
//     res.status(500).json({ error: 'Login failed', detail: (err as Error).message });
//   }
// };

// export const refreshToken = async (req: Request, res: Response): Promise<void> => {
//   const token = req.body.refreshToken || req.cookies?.refreshToken;

//   if (!token) {
//     res.status(401).json({ error: 'Refresh token required' });
//     return;
//   }

//   try {
//     // Check blacklist
//     const isBlacklisted = await redisClient.get(`bl_token:${token}`);
//     if (isBlacklisted) {
//       res.status(403).json({ error: 'Token is blacklisted' });
//       return;
//     }

//     // Verify token & extract payload
//     const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET!) as JwtPayload;
//     const { userId, sessionId } = decoded;

//     // Validate session exists in Redis
//     const redisKey = `${SESSION_PREFIX}${userId}:${sessionId}`;
//     const storedRefreshToken = await redisClient.get(redisKey);

//     if (!storedRefreshToken || storedRefreshToken !== token) {
//       res.status(403).json({ error: 'Invalid refresh token or session expired' });
//       return;
//     }

//     // Generate new access token (no refresh token rotation here)
//     const newAccessToken = generateToken(userId, sessionId, process.env.ACCESS_TOKEN_SECRET!, '15m');

//     res.json({ accessToken: newAccessToken });
//   } catch (err) {
//     res.status(403).json({ error: 'Invalid refresh token', detail: (err as Error).message });
//   }
// };

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
