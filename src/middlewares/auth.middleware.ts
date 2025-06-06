// // import { Request, Response, NextFunction } from 'express';
// // import jwt from 'jsonwebtoken';



// import { Request, Response, NextFunction } from 'express';
// import jwt from 'jsonwebtoken';
// import { redisClient } from '../redisClient'; // Your Redis client

// export const authenticateToken = async (
//   req: Request,
//   res: Response,
//   next: NextFunction
// ): Promise<void> => {
//   const authHeader = req.headers['authorization'];
//   const token = authHeader?.split(' ')[1];

//   if (!token) {
//     res.sendStatus(401);
//     return;
//   }

//   try {
//     // Check if token is blacklisted
//     const isBlacklisted = await redisClient.get(`bl_token:${token}`);
//     if (isBlacklisted) {
//       res.status(401).json({ error: 'Token is blacklisted' });
//       return;
//     }

//     const secret = process.env.ACCESS_TOKEN_SECRET;
//     if (!secret) throw new Error('ACCESS_TOKEN_SECRET not set');

//     jwt.verify(token, secret, (err, decoded) => {
//       if (err) {
//         res.sendStatus(403);
//         return;
//       }

//       (req as any).userId = (decoded as any).userId;
//       next();
//     });
//   } catch (err) {
//     res.status(500).json({ error: 'Token verification failed', detail: (err as Error).message });
//   }
// };


import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { redisClient } from '../redisClient';

export const authenticateToken = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) {
    res.sendStatus(401);
    return;
  }

  try {
    const isBlacklisted = await redisClient.get(`bl_token:${token}`);
    if (isBlacklisted) {
      res.status(401).json({ error: 'Token is blacklisted' });
      return;
    }

    const secret = process.env.ACCESS_TOKEN_SECRET!;
    const decoded = jwt.verify(token, secret) as JwtPayload;

    if (!decoded || !decoded.userId || !decoded.sessionId) {
      res.status(403).json({ error: 'Invalid token payload' });
      return;
    }

    (req as any).userId = decoded.userId;
    (req as any).sessionId = decoded.sessionId;

    next();
  } catch (err) {
    res.status(403).json({ error: 'Token verification failed', detail: (err as Error).message });
  }
};
