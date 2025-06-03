import jwt, { Secret, SignOptions } from 'jsonwebtoken';

export const generateTokens = (
  userId: string | number,
  secret: Secret,
  expiresIn: string
): string => {
  const payload = { userId };
  const options: SignOptions = { expiresIn: expiresIn as any };
  return jwt.sign(payload, secret, options);
};
