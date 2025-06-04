import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
  // connectionString: process.env.DATABASE_URL,
    host:"localhost",
    user:"postgres",
    port:5432,
    password:"Ats@123",
    database: "persondb"
});

pool.connect()
  .then(() => console.log("Connected to PostgreSQL"))
  .catch(err => console.error("DB Connection Error:", err));
  
export default pool;
