import mysql from "mysql2/promise";
import "dotenv/config";

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  connectionLimit: Number(process.env.DB_CONNECTION_LIMIT || 10),
  charset: "utf8mb4",
  // dateStrings: true,  // 날짜를 문자열로 받고 싶을 때 활성화
  // timezone: 'Z',      // 드라이버 레벨 타임존 지정
});

export default pool;
