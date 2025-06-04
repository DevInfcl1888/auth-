import passport from 'passport';
import { Strategy as GoogleStrategy, Profile } from 'passport-google-oauth20';
import dotenv from 'dotenv';
import pool from './db';
import { v4 as uuidv4 } from 'uuid';

dotenv.config();

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID!,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
  callbackURL: process.env.GOOGLE_CALLBACK_URL!,
},
async (
  accessToken: string,
  refreshToken: string,
  profile: Profile,
  done: (error: any, user?: any) => void
) => {
  try {
    const email = profile.emails?.[0]?.value;
    const google_id = profile.id;
    const first_name = profile.name?.givenName || '';
    const last_name = profile.name?.familyName || '';
    const image_url = profile.photos?.[0]?.value || null;

    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    let user;

    if (existingUser.rows.length > 0) {
      user = existingUser.rows[0];
    } else {
      const id = uuidv4();
      const mdr_id = `MDR-${Math.random().toString(36).substr(2, 9)}`;
      const gender = null;
      const password = 'GOOGLE_USER'; // 👈 dummy password
      const provider = 'google';      // 👈 for tracking

      const newUser = await pool.query(`
        INSERT INTO users (
          id, email, first_name, last_name, image_url, google_id, gender, mdr_id, password, provider
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
        ) RETURNING *;
      `, [id, email, first_name, last_name, image_url, google_id, gender, mdr_id, password, provider]);

      user = newUser.rows[0];
    }

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user: Express.User, done) => {
  done(null, user);
});

passport.deserializeUser((obj: Express.User, done) => {
  done(null, obj);
});
