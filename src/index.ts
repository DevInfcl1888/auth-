import express, { Application } from 'express';
import passport from 'passport';
import dotenv from 'dotenv';
import authRoutes from './routes/auth.routes';
import session from 'express-session';
import './passport';

dotenv.config();

// ✅ Define app only once
const app: Application = express();

// ✅ Middlewares
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret_key_here',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true if using HTTPS in production
    httpOnly: true
  }
}));

app.use(express.json());
app.use(passport.initialize());
app.use(passport.session());
console.log('typeof authRoutes:', typeof authRoutes);
// ✅ Routes
app.use('/api', authRoutes); // using only once is sufficient

// ✅ Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
