import express from "express";
import morgan from "morgan";
import cors from "cors";
import usersRouter from "./routes/user.routes.js"; // 예시 라우트
import errorMiddleware from "./middlewares/error.js";
import jwt from "jsonwebtoken";
import verifyToken from "./middlewares/verifyToken.js";
import pool from "./db.js";

const app = express();

const tokenReissue = async (req, res) => {
  try {
    const { refreshToken } = req.body; // body로 통일

    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token missing" });
    }

    jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET,
      async (err, decoded) => {
        if (err) {
          return res.status(401).json({ message: "Invalid refresh token" });
        }

        const { id } = decoded;

        // ✅ admin_users 테이블에서 관리자 확인
        const [rows] = await pool.query(
          `SELECT * FROM admin_users WHERE id = ?`,
          [id],
        );

        const admin = rows[0];
        if (!admin) {
          return res
            .status(404)
            .json({ message: "관리자 사용자를 찾을 수 없습니다." });
        }

        // ✅ Access Token 재발급
        const newAccessToken = jwt.sign(
          {
            id: admin.id,
            role: "admin",
          },
          process.env.JWT_ACCESS_SECRET,
          { expiresIn: "15m" },
        );

        return res.json({
          accessToken: newAccessToken,
        });
      },
    );
  } catch (e) {
    console.error("Token Reissue Error:", e);
    res.status(500).json({ message: "Server error" });
  }
};
// 공통 미들웨어
app.use(cors());
app.use(morgan("dev"));
app.use(express.json()); // JSON Body 파싱
app.use(express.urlencoded({ extended: false })); // 폼 파싱

// 헬스체크
app.get("/health", (req, res) => {
  res.json({ ok: true, now: new Date().toISOString() });
});
app.post("/api/users/token/reissue", tokenReissue);

app.get("/api/room_group", verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT * FROM room_group ORDER BY id ASC`);

    return res.json({
      ok: true,
      data: rows,
    });
  } catch (e) {
    console.error("room_group fetch error:", e);
    res.status(500).json({
      ok: false,
      message: "room_group 조회 중 오류 발생",
    });
  }
});

// 예시 라우트(원하시는 테이블 라우터로 교체/추가)
app.use("/api/users", usersRouter);

// 404 핸들러
app.use((req, res, next) => {
  res.status(404).json({ message: "Not Found" });
});

// 에러 핸들러
app.use(errorMiddleware);

export default app;
