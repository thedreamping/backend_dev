import express from "express";
import morgan from "morgan";
import cors from "cors";
import usersRouter from "./routes/user.routes.js"; // 예시 라우트
import errorMiddleware from "./middlewares/error.js";
import jwt from "jsonwebtoken";
import verifyToken from "./middlewares/verifyToken.js";
import pool from "./db.js";
import multer from "multer";
import path from "path";
const app = express();

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const basename = path.basename(file.originalname, ext);
    // 파일명-날짜.확장자 형태로 깔끔하게 저장!
    cb(null, `${basename}-${Date.now()}${ext}`);
  },
});

const upload = multer({ storage: storage });

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

app.get("/api/rooms", verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT * FROM room ORDER BY id ASC`);

    return res.json({
      ok: true,
      data: rows,
    });
  } catch (e) {
    console.error("room fetch error:", e);
    res.status(500).json({
      ok: false,
      message: "room 조회 중 오류 발생",
    });
  }
});

app.get("/api/options", verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT * FROM options ORDER BY id ASC`);

    return res.json({
      ok: true,
      data: rows,
    });
  } catch (e) {
    console.error("options fetch error:", e);
    res.status(500).json({
      ok: false,
      message: "options 조회 중 오류 발생",
    });
  }
});
app.post("/api/main-banner", upload.array("file"), async (req, res) => {
  try {
    const files = req.files || [];

    // multer + formData 특성상
    const normalizeToArray = (value) => {
      if (!value) return [];
      return Array.isArray(value) ? value : [value];
    };

    const file_name = normalizeToArray(req.body.file_name);
    const text = normalizeToArray(req.body.text);
    const link = normalizeToArray(req.body.link);
    const file_url = normalizeToArray(req.body.file_url);
    const file_index = normalizeToArray(req.body.file_index); // 새 파일의 슬라이드 index

    // 필수값 체크
    if (!text.length || text.length !== link.length) {
      return res.status(400).json({ message: "데이터 형식 오류" });
    }

    // 🔥 기존 데이터 전체 삭제
    await pool.query("DELETE FROM main_banners");

    // 새 파일과 슬라이드를 index로 매칭
    const fileMap = {}; // index: fileUrl
    files.forEach((file, idx) => {
      const index = parseInt(file_index[idx], 10);
      if (!isNaN(index)) {
        fileMap[index] = `/uploads/${file.filename}`;
      }
    });

    for (let i = 0; i < text.length; i++) {
      let finalFileUrl;

      // 새 파일이 있으면 해당 index에서 가져오기
      if (fileMap[i]) {
        finalFileUrl = fileMap[i];
      }
      // 새 파일 없으면 기존 파일 유지
      else if (file_url[i]) {
        finalFileUrl = file_url[i];
      }
      // 둘 다 없으면 에러
      else {
        return res.status(400).json({
          message: `이미지 파일이 누락되었습니다. index: ${i}`,
        });
      }

      await pool.query(
        `
        INSERT INTO main_banners (file_name, text, link, file_url)
        VALUES (?, ?, ?, ?)
        `,
        [file_name[i] || "", text[i], link[i], finalFileUrl],
      );
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("main-banner save error:", err);
    return res.status(500).json({ message: "서버 오류" });
  }
});

app.get("/api/get-main-banner", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM main_banners ORDER BY id ASC`,
    );

    return res.json({
      ok: true,
      data: rows,
    });
  } catch (err) {
    console.error("main-banner fetch error:", err);
    return res.status(500).json({
      ok: false,
      message: "메인 배너 조회 중 오류 발생",
    });
  }
});

app.post("/api/room-price", verifyToken, async (req, res) => {
  try {
    const { dates, rooms } = req.body;

    if (!dates || !rooms || !Array.isArray(dates) || !Array.isArray(rooms)) {
      return res.status(400).json({
        ok: false,
        message: "잘못된 요청 형식입니다.",
      });
    }

    const insertValues = [];

    for (const date of dates) {
      for (const room of rooms) {
        const price = Number(room.price);

        if (!room.room_group_id || !room.room_group_name) continue;
        if (!price || price <= 0) continue;

        insertValues.push([
          room.room_group_id,
          date,
          price,
          room.room_group_name,
        ]);
      }
    }

    if (insertValues.length === 0) {
      return res.status(400).json({
        ok: false,
        message: "저장할 가격 데이터가 없습니다.",
      });
    }

    await pool.query(
      `
      INSERT INTO room_price 
      (room_group_id, date, price, room_group_name)
      VALUES ?
      ON DUPLICATE KEY UPDATE
        price = VALUES(price),
        room_group_name = VALUES(room_group_name)
      `,
      [insertValues],
    );

    return res.json({
      ok: true,
      message: "객실 가격 저장(덮어쓰기) 완료",
    });
  } catch (error) {
    console.error("room_price upsert error:", error);
    return res.status(500).json({
      ok: false,
      message: "객실 가격 저장 중 오류 발생",
    });
  }
});
app.get("/api/room-price", verifyToken, async (req, res) => {
  try {
    let { year, month, roomId } = req.query;

    if (!year || !month) {
      return res.status(400).json({
        ok: false,
        message: "year, month는 필수입니다.",
      });
    }

    month = String(month).padStart(2, "0");

    // 시작일
    const startDate = `${year}-${month}-01`;

    // 다음 달 계산
    const nextMonthDate = new Date(Number(year), Number(month), 1);
    const nextYear = nextMonthDate.getFullYear();
    const nextMonthStr = String(nextMonthDate.getMonth() + 1).padStart(2, "0");
    const endDate = `${nextYear}-${nextMonthStr}-01`;

    let query = `
      SELECT
        id,
        room_group_id,
        room_group_name,
        price,
        DATE_FORMAT(date, '%Y-%m-%d') AS date
      FROM room_price
      WHERE date >= ? AND date < ?
    `;

    const params = [startDate, endDate];

    // roomId 선택 조건
    if (roomId !== undefined && roomId !== null && roomId !== "") {
      const parsedRoomId = Number(roomId);
      if (!isNaN(parsedRoomId)) {
        query += ` AND room_group_id = ?`;
        params.push(parsedRoomId);
      }
    }

    query += ` ORDER BY date ASC`;

    const [rows] = await pool.query(query, params);

    return res.json({
      ok: true,
      data: rows,
    });
  } catch (error) {
    console.error("room_price fetch error:", error);
    return res.status(500).json({
      ok: false,
      message: "객실 가격 조회 중 오류 발생",
    });
  }
});

// 예시 라우트(원하시는 테이블 라우터로 교체/추가)
app.use("/api/users", usersRouter);

app.use("/uploads", express.static("uploads"));

// 404 핸들러
app.use((req, res, next) => {
  res.status(404).json({ message: "Not Found" });
});

// 에러 핸들러
app.use(errorMiddleware);

export default app;
