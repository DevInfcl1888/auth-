import crypto from 'crypto';

export const generateSalt = (): string => {
  return crypto.randomBytes(16).toString('hex');
};

export const hashPassword = (password: string, salt: string): string => {
  return crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
};

export const verifyPassword = (password: string, hashedPassword: string, salt: string): boolean => {
  const hash = hashPassword(password, salt);
  return hash === hashedPassword;
};
