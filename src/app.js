import express from "express";
import crypto from "crypto";
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
  res.json({ ok: true, now: new Date().toISOString(), test: "잘 되었음" });
});
app.post("/api/users/token/reissue", tokenReissue);

app.get("/api/room_group", async (req, res) => {
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

app.get("/api/rooms", async (req, res) => {
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

app.get("/api/options", async (req, res) => {
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

app.put("/api/options/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      price,
      start_date,
      end_date,
      start_date_able,
      end_date_able,
    } = req.body;

    // 🔎 필수값 체크
    if (
      !name ||
      !price ||
      !start_date ||
      !end_date ||
      !start_date_able ||
      !end_date_able
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "name, price, start_date, end_date,  start_date_able, end_date_able  는 필수입니다.",
      });
    }

    // 🔎 날짜 유효성 체크 (선택사항이지만 추천)
    if (new Date(start_date) > new Date(end_date)) {
      return res.status(400).json({
        ok: false,
        message: "start_date는 end_date보다 클 수 없습니다.",
      });
    }

    // 🔎 날짜 유효성 체크 (선택사항이지만 추천)
    if (new Date(start_date_able) > new Date(end_date_able)) {
      return res.status(400).json({
        ok: false,
        message: "start_date는 end_date보다 클 수 없습니다.",
      });
    }

    const [result] = await pool.query(
      `
      UPDATE options
      SET name = ?,
          price = ?,
          start_date = ?,
          end_date = ?,
          start_date_able = ?,
          end_date_able = ?
      WHERE id = ?
      `,
      [
        name,
        Number(price),
        start_date,
        end_date,
        start_date_able,
        end_date_able,
        id,
      ],
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        ok: false,
        message: "해당 옵션을 찾을 수 없습니다.",
      });
    }

    return res.json({
      ok: true,
      message: "옵션 수정 완료",
    });
  } catch (error) {
    console.error("options update error:", error);
    return res.status(500).json({
      ok: false,
      message: "옵션 수정 중 오류 발생",
    });
  }
});

app.post("/api/options", verifyToken, async (req, res) => {
  try {
    const {
      name,
      price,
      start_date,
      end_date,
      start_date_able,
      end_date_able,
    } = req.body;

    // 🔎 필수값 체크
    if (
      !name ||
      price === undefined ||
      !start_date ||
      !end_date ||
      !start_date_able ||
      !end_date_able
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "name, price, start_date, end_date, start_date_able, end_date_able 는 필수입니다.",
      });
    }

    const numericPrice = Number(price);

    if (isNaN(numericPrice) || numericPrice < 0) {
      return res.status(400).json({
        ok: false,
        message: "price는 0 이상 숫자여야 합니다.",
      });
    }

    // 🔎 날짜 유효성 체크
    if (new Date(start_date) > new Date(end_date)) {
      return res.status(400).json({
        ok: false,
        message: "start_date는 end_date보다 클 수 없습니다.",
      });
    }

    if (new Date(start_date_able) > new Date(end_date_able)) {
      return res.status(400).json({
        ok: false,
        message: "start_date_able는 end_date_able보다 클 수 없습니다.",
      });
    }

    // 🔥 예약 가능 기간이 옵션 기간 안에 포함되는지 체크
    if (
      new Date(start_date_able) < new Date(start_date) ||
      new Date(end_date_able) > new Date(end_date)
    ) {
      return res.status(400).json({
        ok: false,
        message: "예약 가능 기간은 옵션 기간 안에 포함되어야 합니다.",
      });
    }

    const [result] = await pool.query(
      `
      INSERT INTO options
      (name, price, start_date, end_date, start_date_able, end_date_able, is_use)
      VALUES (?, ?, ?, ?, ?, ?, 1)
      `,
      [
        name,
        numericPrice,
        start_date,
        end_date,
        start_date_able,
        end_date_able,
      ],
    );

    return res.json({
      ok: true,
      message: "옵션 생성 완료",
      id: result.insertId,
    });
  } catch (error) {
    console.error("options create error:", error);
    return res.status(500).json({
      ok: false,
      message: "옵션 생성 중 오류 발생",
    });
  }
});

app.delete("/api/options/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({
        ok: false,
        message: "옵션 ID는 필수입니다.",
      });
    }

    const [result] = await pool.query(`DELETE FROM options WHERE id = ?`, [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({
        ok: false,
        message: "해당 옵션을 찾을 수 없습니다.",
      });
    }

    return res.json({
      ok: true,
      message: "옵션 삭제 완료",
    });
  } catch (error) {
    console.error("options delete error:", error);
    return res.status(500).json({
      ok: false,
      message: "옵션 삭제 중 오류 발생",
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

app.post("/api/main-room-banner", upload.array("file"), async (req, res) => {
  try {
    const files = req.files || [];

    // multer + formData 특성상
    const normalizeToArray = (value) => {
      if (!value) return [];
      return Array.isArray(value) ? value : [value];
    };

    const file_name = normalizeToArray(req.body.file_name);
    const text = normalizeToArray(req.body.text);
    const title = normalizeToArray(req.body.title);
    const link = normalizeToArray(req.body.link);
    const file_url = normalizeToArray(req.body.file_url);
    const file_index = normalizeToArray(req.body.file_index); // 새 파일의 슬라이드 index

    // 필수값 체크
    if (
      !text.length ||
      text.length !== link.length ||
      text.length !== title.length
    ) {
      return res.status(400).json({ message: "데이터 형식 오류" });
    }

    // 🔥 기존 데이터 전체 삭제
    await pool.query("DELETE FROM main_room_banners");

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
        INSERT INTO main_room_banners (file_name, text, link, file_url, title)
        VALUES (?, ?, ?, ?, ?)
        `,
        [file_name[i] || "", text[i], link[i], finalFileUrl, title[i]],
      );
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("main-banner save error:", err);
    return res.status(500).json({ message: "서버 오류" });
  }
});

app.post("/api/main-dining-banner", upload.array("file"), async (req, res) => {
  try {
    const files = req.files || [];

    // multer + formData 특성상
    const normalizeToArray = (value) => {
      if (!value) return [];
      return Array.isArray(value) ? value : [value];
    };

    const file_name = normalizeToArray(req.body.file_name);
    const text = normalizeToArray(req.body.text);
    const title = normalizeToArray(req.body.title);
    const link = normalizeToArray(req.body.link);
    const file_url = normalizeToArray(req.body.file_url);
    const file_index = normalizeToArray(req.body.file_index); // 새 파일의 슬라이드 index

    // 필수값 체크
    if (
      !text.length ||
      text.length !== link.length ||
      text.length !== title.length
    ) {
      return res.status(400).json({ message: "데이터 형식 오류" });
    }

    // 🔥 기존 데이터 전체 삭제
    await pool.query("DELETE FROM main_dining_banners");

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
        INSERT INTO main_dining_banners (file_name, text, link, file_url, title)
        VALUES (?, ?, ?, ?, ?)
        `,
        [file_name[i] || "", text[i], link[i], finalFileUrl, title[i]],
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

app.get("/api/get-main-room-banner", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM main_room_banners ORDER BY id ASC`,
    );

    return res.json({
      ok: true,
      data: rows,
    });
  } catch (err) {
    console.error("main-room-banner fetch error:", err);
    return res.status(500).json({
      ok: false,
      message: "메인 룸 배너 조회 중 오류 발생",
    });
  }
});

app.get("/api/get-main-dining-banner", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM main_dining_banners ORDER BY id ASC`,
    );

    return res.json({
      ok: true,
      data: rows,
    });
  } catch (err) {
    console.error("main-dining-banner fetch error:", err);
    return res.status(500).json({
      ok: false,
      message: "메인 룸 배너 조회 중 오류 발생",
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
app.get("/api/room-price", async (req, res) => {
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

app.put("/api/room/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    const { name, is_active, reason, capacity_max, capacity_min, day_use } =
      req.body;

    // ✅ 필수값 체크
    if (
      !name ||
      typeof is_active === "undefined" ||
      capacity_max === undefined ||
      capacity_min === undefined ||
      day_use === undefined
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "name, is_active, capacity_max, capacity_min, day_use는 필수입니다.",
      });
    }

    const numericMax = Number(capacity_max);
    const numericMin = Number(capacity_min);
    const numericDayUse = Number(day_use);

    if (isNaN(numericMax) || isNaN(numericMin) || numericMax < numericMin) {
      return res.status(400).json({
        ok: false,
        message: "capacity 값이 올바르지 않습니다.",
      });
    }

    if (numericDayUse !== 0 && numericDayUse !== 1) {
      return res.status(400).json({
        ok: false,
        message: "day_use는 0 또는 1이어야 합니다.",
      });
    }

    // 🔥 비활성화 시 사유 필수
    if (Number(is_active) === 0 && (!reason || reason.trim() === "")) {
      return res.status(400).json({
        ok: false,
        message: "비활성화 시 사유는 필수입니다.",
      });
    }

    const finalReason = Number(is_active) === 1 ? null : reason.trim();
    const lodgement = numericDayUse === 1 ? 0 : 1;

    // ✅ 1️⃣ 해당 room의 group id 조회
    const [roomRows] = await pool.query(
      `SELECT room_group_id FROM room WHERE id = ?`,
      [id],
    );

    if (roomRows.length === 0) {
      return res.status(404).json({
        ok: false,
        message: "해당 객실을 찾을 수 없습니다.",
      });
    }

    const roomGroupId = roomRows[0].room_group_id;

    // ✅ 2️⃣ 그룹 전체 capacity/day_use/lodgement 일괄 수정
    await pool.query(
      `
      UPDATE room
      SET capacity_max = ?,
          capacity_min = ?,
          day_use = ?,
          lodgement = ?
      WHERE room_group_id = ?
      `,
      [numericMax, numericMin, numericDayUse, lodgement, roomGroupId],
    );

    // ✅ 3️⃣ 해당 id 하나만 name/is_active/reason 수정
    const [result] = await pool.query(
      `
      UPDATE room
      SET name = ?,
          is_active = ?,
          reason = ?
      WHERE id = ?
      `,
      [name.trim(), Number(is_active), finalReason, id],
    );

    return res.json({
      ok: true,
      message: "객실 정보 수정 완료",
    });
  } catch (error) {
    console.error("room update error:", error);
    return res.status(500).json({
      ok: false,
      message: "객실 수정 중 오류 발생",
    });
  }
});

app.put("/api/room-group/:id", verifyToken, async (req, res) => {
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const { id } = req.params;
    const { name, is_active, reason } = req.body;

    if (!name || typeof is_active === "undefined") {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        message: "name, is_active는 필수입니다.",
      });
    }

    if (Number(is_active) === 0 && (!reason || reason.trim() === "")) {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        message: "비활성화 시 사유는 필수입니다.",
      });
    }

    const finalReason = Number(is_active) === 1 ? null : reason.trim();

    // 1️⃣ 그룹 업데이트
    const [result] = await connection.query(
      `
      UPDATE room_group
      SET name = ?, is_active = ?, reason = ?
      WHERE id = ?
      `,
      [name, Number(is_active), finalReason, id],
    );

    if (result.affectedRows === 0) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        message: "해당 객실 그룹을 찾을 수 없습니다.",
      });
    }

    // 2️⃣ 그룹이 비활성화면 하위 room도 비활성화
    if (Number(is_active) === 0) {
      await connection.query(
        `
        UPDATE room
        SET is_active = 0,
            reason = '상위 그룹 비활성화'
        WHERE room_group_id = ?
        `,
        [id],
      );
    }

    // 3️⃣ 그룹이 활성화면 하위 room도 활성화 + reason NULL
    if (Number(is_active) === 1) {
      await connection.query(
        `
        UPDATE room
        SET is_active = 1,
            reason = NULL
        WHERE room_group_id = ?
        `,
        [id],
      );
    }

    await connection.commit();

    return res.json({
      ok: true,
      message: "객실 그룹 수정 완료",
    });
  } catch (error) {
    await connection.rollback();
    console.error("room_group update error:", error);
    return res.status(500).json({
      ok: false,
      message: "객실 그룹 수정 중 오류 발생",
    });
  } finally {
    connection.release();
  }
});

app.delete("/api/room/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    const [result] = await pool.query(`DELETE FROM room WHERE id = ?`, [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({
        ok: false,
        message: "해당 객실을 찾을 수 없습니다.",
      });
    }

    return res.json({
      ok: true,
      message: "객실 삭제 완료",
    });
  } catch (error) {
    console.error("room delete error:", error);
    return res.status(500).json({
      ok: false,
      message: "객실 삭제 중 오류 발생",
    });
  }
});

app.delete("/api/room-group/:id", verifyToken, async (req, res) => {
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const { id } = req.params;

    // 1️⃣ 하위 룸 삭제
    await connection.query(`DELETE FROM room WHERE room_group_id = ?`, [id]);

    // 2️⃣ 그룹 삭제
    const [result] = await connection.query(
      `DELETE FROM room_group WHERE id = ?`,
      [id],
    );

    if (result.affectedRows === 0) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        message: "해당 객실 그룹을 찾을 수 없습니다.",
      });
    }

    await connection.commit();

    return res.json({
      ok: true,
      message: "객실 그룹 및 하위 룸 삭제 완료",
    });
  } catch (error) {
    await connection.rollback();
    console.error("room_group delete error:", error);
    return res.status(500).json({
      ok: false,
      message: "객실 그룹 삭제 중 오류 발생",
    });
  } finally {
    connection.release();
  }
});

app.post("/api/room-group", verifyToken, async (req, res) => {
  try {
    const { name, description } = req.body;

    // 🔎 필수값 체크
    if (!name || name.trim() === "") {
      return res.status(400).json({
        ok: false,
        message: "name은 필수입니다.",
      });
    }

    // 🔥 description은 선택값으로 처리 가능
    const finalDescription =
      description && description.trim() !== "" ? description.trim() : null;

    const [result] = await pool.query(
      `
      INSERT INTO room_group
      (name, description, is_active, reason)
      VALUES (?, ?, 1, NULL)
      `,
      [name.trim(), finalDescription],
    );

    return res.json({
      ok: true,
      message: "객실 그룹 생성 완료",
      id: result.insertId,
    });
  } catch (error) {
    console.error("room_group create error:", error);
    return res.status(500).json({
      ok: false,
      message: "객실 그룹 생성 중 오류 발생",
    });
  }
});

app.post("/api/room", verifyToken, async (req, res) => {
  try {
    const {
      name,
      description,
      room_group_id,
      capacity_max,
      capacity_min,
      day_use,
    } = req.body;

    // ✅ 필수값 체크
    if (
      !name ||
      !room_group_id ||
      capacity_max === undefined ||
      capacity_min === undefined ||
      day_use === undefined
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "name, room_group_id, capacity_max, capacity_min, day_use는 필수입니다.",
      });
    }

    const numericMax = Number(capacity_max);
    const numericMin = Number(capacity_min);
    const numericDayUse = Number(day_use);

    if (isNaN(numericMax) || isNaN(numericMin) || numericMax < numericMin) {
      return res.status(400).json({
        ok: false,
        message: "capacity 값이 올바르지 않습니다.",
      });
    }

    if (numericDayUse !== 0 && numericDayUse !== 1) {
      return res.status(400).json({
        ok: false,
        message: "day_use는 0 또는 1이어야 합니다.",
      });
    }

    // 🔥 lodgement 자동 결정
    const lodgement = numericDayUse === 1 ? 0 : 1;

    const finalDescription =
      description && description.trim() !== "" ? description.trim() : null;

    const [result] = await pool.query(
      `
      INSERT INTO room
      (
        name,
        description,
        capacity_max,
        capacity_min,
        room_group_id,
        available,
        is_active,
        day_use,
        lodgement,
        reason
      )
      VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?, NULL)
      `,
      [
        name.trim(),
        finalDescription,
        numericMax,
        numericMin,
        room_group_id,
        numericDayUse,
        lodgement,
      ],
    );

    return res.json({
      ok: true,
      message: "객실 생성 완료",
      id: result.insertId,
    });
  } catch (error) {
    console.error("room create error:", error);
    return res.status(500).json({
      ok: false,
      message: "객실 생성 중 오류 발생",
    });
  }
});

app.post("/api/reservation", async (req, res) => {
  try {
    const {
      name,
      phone,
      email,
      memo,
      startDate,
      endDate,
      roomInfo,
      options,
      price,
    } = req.body;

    if (!name || !phone || !startDate || !endDate || !roomInfo) {
      return res.status(400).json({
        ok: false,
        message: "필수값 누락",
      });
    }

    const numericPrice = Number(price);

    if (isNaN(numericPrice) || numericPrice <= 0) {
      return res.status(400).json({
        ok: false,
        message: "금액 오류",
      });
    }

    const check_in = startDate;
    const check_out = endDate;

    const nights = Math.ceil(
      (new Date(check_out) - new Date(check_in)) / (1000 * 60 * 60 * 24),
    );

    const [result] = await pool.query(
      `
    
      INSERT INTO reservations_info
      (
        room_id,
        room_group_id,
        check_in,
        check_out,
        nights,
        total_amount,
        status,
        buyer_name,
        buyer_tel,
        buyer_email,
        memo,
        options,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, NOW(), NOW())
      `,
      [
        1,
        roomInfo.room_group_id,
        check_in,
        check_out,
        nights,
        numericPrice,
        name.trim(),
        phone.trim(),
        email ? email.trim() : null,
        memo ? memo.trim() : null,
        options ? JSON.stringify(options) : null,
      ],
    );

    return res.json({
      ok: true,
      reservationId: result.insertId,
    });
  } catch (error) {
    console.error("reservation create error:", error);

    return res.status(500).json({
      ok: false,
      message: "예약 저장 실패",
    });
  }
});

app.post("/api/payment/ready", async (req, res) => {
  try {
    const { reservationId } = req.body;

    if (!reservationId) {
      return res.status(400).json({
        ok: false,
        message: "reservationId 필요",
      });
    }

    const [rows] = await pool.query(
      "SELECT * FROM reservations_info WHERE id = ?",
      [reservationId],
    );

    if (rows.length === 0) {
      return res.status(404).json({
        ok: false,
        message: "예약 정보 없음",
      });
    }

    const reservation = rows[0];

    if (reservation.status !== "PENDING") {
      return res.status(400).json({
        ok: false,
        message: "이미 처리된 예약입니다.",
      });
    }

    const mid = "INIpayTest";
    const signKey = "SU5JTElURV9UUklQTEVERVNfS0VZU1RS";

    const oid = `ORD-${reservation.id}-${Date.now()}`;
    const timestamp = Date.now().toString();
    const price = reservation.total_amount.toString();

    const signature = crypto
      .createHash("sha256")
      .update(`oid=${oid}&price=${price}&timestamp=${timestamp}`)
      .digest("hex");

    const verification = crypto
      .createHash("sha256")
      .update(
        `oid=${oid}&price=${price}&signKey=${signKey}&timestamp=${timestamp}`,
      )
      .digest("hex");

    const mKey = crypto.createHash("sha256").update(signKey).digest("hex");

    await pool.query(
      "UPDATE reservations_info SET order_id = ?, updated_at = NOW() WHERE id = ?",
      [oid, reservation.id],
    );

    return res.json({
      ok: true,
      mid,
      oid,
      price,
      timestamp,
      signature,
      verification,
      mKey,
      returnUrl:
        process.env.INICIS_RETURN_URL ||
        "https://localhost:4000/api/payment/return",
    });
  } catch (error) {
    console.error("payment ready error:", error);

    return res.status(500).json({
      ok: false,
      message: "결제 준비 중 오류 발생",
    });
  }
});

app.post("/api/dk_schedule", verifyToken, async (req, res) => {
  try {
    const { days, schedule_name, schedule_contents, color } = req.body;

    // 필수값 체크
    if (!days || !Array.isArray(days) || days.length === 0 || !schedule_name) {
      return res.status(400).json({
        ok: false,
        message: "days 배열과 schedule_name은 필수입니다.",
      });
    }

    const [result] = await pool.query(
      `
      INSERT INTO dk_schedules
      (days, schedule_name, schedule_contents, color, created_at)
      VALUES (?, ?, ?, ?, NOW())
      `,
      [
        JSON.stringify(days),
        schedule_name.trim(),
        schedule_contents ? schedule_contents.trim() : null,
        color,
      ],
    );

    return res.json({
      ok: true,
      message: "스케줄 생성 완료",
      id: result.insertId,
    });
  } catch (error) {
    console.error("dk_schedule create error:", error);

    return res.status(500).json({
      ok: false,
      message: "스케줄 생성 중 오류 발생",
    });
  }
});
app.get("/api/dk_schedule", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT id, days, schedule_name, schedule_contents, color, created_at
      FROM dk_schedules
      ORDER BY id DESC
    `);

    const data = rows.map((row) => ({
      ...row,
      days: typeof row.days === "string" ? JSON.parse(row.days) : row.days,
    }));

    return res.json({
      ok: true,
      data,
    });
  } catch (error) {
    console.error("dk_schedule fetch error:", error);

    return res.status(500).json({
      ok: false,
      message: "스케줄 조회 중 오류 발생",
    });
  }
});
app.put("/api/dk_schedule/remove-day", async (req, res) => {
  try {
    const { schedule_id, year, month, day } = req.body;

    const [rows] = await pool.query("SELECT * FROM dk_schedules WHERE id = ?", [
      schedule_id,
    ]);

    if (rows.length === 0) {
      return res.status(404).json({
        result: "fail",
        message: "schedule not found",
      });
    }

    const schedule = rows[0];

    let days = [];

    if (schedule.days) {
      days =
        typeof schedule.days === "string"
          ? JSON.parse(schedule.days)
          : schedule.days;
    }

    const newDays = days.filter(
      (d) => !(d.year === year && d.month === month && d.day === day),
    );

    await pool.query("UPDATE dk_schedules SET days = ? WHERE id = ?", [
      JSON.stringify(newDays),
      schedule_id,
    ]);

    res.json({
      result: "success",
    });
  } catch (err) {
    console.error("remove schedule day error:", err);
    res.status(500).json({
      result: "fail",
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
