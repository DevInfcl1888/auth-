import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();
const connectionString = `postgresql://${encodeURIComponent(process.env.DB_USER!)}:${encodeURIComponent(process.env.DB_PASSWORD!)}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME_IN}`;

const pool = new Pool({
  connectionString: connectionString,
});

export default pool;
