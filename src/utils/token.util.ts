import jwt from 'jsonwebtoken';

export const generateResetToken = (email: string): string => {
  return jwt.sign({ email }, process.env.RESET_PASSWORD_SECRET!, {
    expiresIn: '15m',
  });
};

export const verifyResetToken = (token: string): string | null => {
  try {
    const decoded = jwt.verify(token, process.env.RESET_PASSWORD_SECRET!) as { email: string };
    return decoded.email;
  } catch {
    return null;
  }
};
