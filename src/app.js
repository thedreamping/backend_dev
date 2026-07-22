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
import qs from "querystring";
import axios from "axios";
import { SolapiMessageService } from "solapi";

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
app.use(express.urlencoded({ extended: true }));

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
    const [rooms] = await pool.query(`
      SELECT
        *,
        0 AS is_extra
      FROM room
    `);

    const [extras] = await pool.query(`
      SELECT
        extra_id AS id,
        name,
        description,

        capacity_min,
        capacity_max,
        capacity_min_dayuse,
        capacity_max_dayuse,

        created_at,
        room_group_id,
        available,
        is_active,
        day_use,
        lodgement,
        reason,
        disable_start,
        disable_end,
        is_ota,
        check_in,
        check_out,
        is_soogie,
        check_in_and_out,
        check_in_and_out_soogie,
        soogie,
        naver_crawling_info,
        start_date,
        end_date,
        extra_id,
        is_pet,

        1 AS is_extra
      FROM extra_room
    `);

    return res.json({
      ok: true,
      data: [...rooms, ...extras],
    });
  } catch (e) {
    console.error("room fetch error:", e);

    return res.status(500).json({
      ok: false,
      message: "room 조회 중 오류 발생",
    });
  }
});

app.get("/api/options", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        id,
        name,
        price,
        DATE_FORMAT(start_date, '%Y-%m-%d') AS start_date,
        DATE_FORMAT(end_date, '%Y-%m-%d') AS end_date,
        DATE_FORMAT(start_date_able, '%Y-%m-%d') AS start_date_able,
        DATE_FORMAT(end_date_able, '%Y-%m-%d') AS end_date_able,
        is_use
      FROM options
      ORDER BY id ASC
    `);

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

app.get("/api/refund-info", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT *
      FROM refund_info
      ORDER BY id ASC
    `);

    return res.json({
      ok: true,
      data: rows,
    });
  } catch (error) {
    console.error("refund_info fetch error:", error);
    return res.status(500).json({
      ok: false,
      message: "환불 정보 조회 중 오류 발생",
    });
  }
});

app.put("/api/refund-info/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { changed } = req.body;

    if (changed === undefined || changed === null) {
      return res.status(400).json({
        ok: false,
        message: "changed 값은 필수입니다.",
      });
    }

    const numericChanged = Number(changed);

    if (isNaN(numericChanged) || numericChanged < 0 || numericChanged > 100) {
      return res.status(400).json({
        ok: false,
        message: "0~100 사이 숫자만 가능합니다.",
      });
    }

    const [result] = await pool.query(
      `
      UPDATE refund_info
      SET per = ?
      WHERE id = ?
      `,
      [numericChanged, id],
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        ok: false,
        message: "해당 환불 정책을 찾을 수 없습니다.",
      });
    }

    return res.json({
      ok: true,
      message: "환불 정책 수정 완료",
    });
  } catch (error) {
    console.error("refund_info update error:", error);

    return res.status(500).json({
      ok: false,
      message: "환불 정책 수정 중 오류 발생",
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

const formatDate = (isoString) => {
  if (!isoString) return null;
  return isoString.split("T")[0]; // YYYY-MM-DD
};

app.post("/api/options_all_change", verifyToken, async (req, res) => {
  try {
    const { options } = req.body;

    if (!Array.isArray(options) || options.length === 0) {
      return res.status(400).json({
        ok: false,
        message: "options 배열이 필요합니다.",
      });
    }

    const conn = await pool.getConnection();
    await conn.beginTransaction();

    try {
      // 🔥 기존 데이터 전부 삭제
      await conn.query(`DELETE FROM options`);

      // 🔥 새로 insert
      for (const item of options) {
        await conn.query(
          `
          INSERT INTO options
          (name, price, start_date, end_date, start_date_able, end_date_able, is_use)
          VALUES (?, ?, ?, ?, ?, ?, 1)
          `,
          [
            item.name,
            Number(item.price),
            formatDate(item.start_date),
            formatDate(item.end_date),
            formatDate(item.start_date_able),
            formatDate(item.end_date_able),
          ],
        );
      }

      await conn.commit();
      conn.release();

      return res.json({
        ok: true,
        message: "전체 재정렬 완료",
      });
    } catch (err) {
      await conn.rollback();
      conn.release();
      throw err;
    }
  } catch (error) {
    console.error("options_all_change error:", error);
    return res.status(500).json({
      ok: false,
      message: "순서 변경 중 오류 발생",
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

app.post(
  "/api/main-banner",
  verifyToken,
  upload.array("file"),
  async (req, res) => {
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
  },
);

app.post(
  "/api/special-offer",
  verifyToken,
  upload.array("file"),
  async (req, res) => {
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
      const price = normalizeToArray(req.body.price);
      const period = normalizeToArray(req.body.period);
      const file_index = normalizeToArray(req.body.file_index); // 새 파일의 슬라이드 index

      // 필수값 체크
      if (!text.length || text.length !== link.length) {
        return res.status(400).json({ message: "데이터 형식 오류" });
      }

      if (!price.length || price.length !== link.length) {
        return res.status(400).json({ message: "데이터 형식 오류" });
      }

      if (!period.length || period.length !== link.length) {
        return res.status(400).json({ message: "데이터 형식 오류" });
      }

      // 🔥 기존 데이터 전체 삭제
      await pool.query("DELETE FROM special_offer");

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
        INSERT INTO special_offer (file_name, text, link, file_url, period, price)
        VALUES (?, ?, ?, ?, ?, ?)
        `,
          [
            file_name[i] || "",
            text[i],
            link[i],
            finalFileUrl,
            period[i],
            price[i],
          ],
        );
      }

      return res.json({ ok: true });
    } catch (err) {
      console.error("special-offer save error:", err);
      return res.status(500).json({ message: "서버 오류" });
    }
  },
);

app.post(
  "/api/ledger-ticket",
  verifyToken,
  upload.array("file"),
  async (req, res) => {
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
      const price = normalizeToArray(req.body.price);
      const period = normalizeToArray(req.body.period);
      const file_index = normalizeToArray(req.body.file_index); // 새 파일의 슬라이드 index

      // 필수값 체크
      if (!text.length || text.length !== link.length) {
        return res.status(400).json({ message: "데이터 형식 오류" });
      }

      if (!price.length || price.length !== link.length) {
        return res.status(400).json({ message: "데이터 형식 오류" });
      }

      if (!period.length || period.length !== link.length) {
        return res.status(400).json({ message: "데이터 형식 오류" });
      }

      // 🔥 기존 데이터 전체 삭제
      await pool.query("DELETE FROM ledger_ticket_bn");

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
        INSERT INTO ledger_ticket_bn (file_name, text, link, file_url, period, price)
        VALUES (?, ?, ?, ?, ?, ?)
        `,
          [
            file_name[i] || "",
            text[i],
            link[i],
            finalFileUrl,
            period[i],
            price[i],
          ],
        );
      }

      return res.json({ ok: true });
    } catch (err) {
      console.error("special-offer save error:", err);
      return res.status(500).json({ message: "서버 오류" });
    }
  },
);

app.post(
  "/api/around-and-spot",
  verifyToken,
  upload.array("file"),
  async (req, res) => {
    try {
      const files = req.files || [];

      // multer + formData 특성상
      const normalizeToArray = (value) => {
        if (!value) return [];
        return Array.isArray(value) ? value : [value];
      };

      const file_name = normalizeToArray(req.body.file_name);

      const file_url = normalizeToArray(req.body.file_url);

      const file_index = normalizeToArray(req.body.file_index); // 새 파일의 슬라이드 index

      // 🔥 기존 데이터 전체 삭제
      await pool.query("DELETE FROM around_and_spot");

      // 새 파일과 슬라이드를 index로 매칭
      const fileMap = {}; // index: fileUrl
      files.forEach((file, idx) => {
        const index = parseInt(file_index[idx], 10);
        if (!isNaN(index)) {
          fileMap[index] = `/uploads/${file.filename}`;
        }
      });

      for (let i = 0; i < file_name.length; i++) {
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
        INSERT INTO around_and_spot (file_name, file_url)
        VALUES (?, ?)
        `,
          [file_name[i] || "", finalFileUrl],
        );
      }

      return res.json({ ok: true });
    } catch (err) {
      console.error("special-offer save error:", err);
      return res.status(500).json({ message: "서버 오류" });
    }
  },
);

app.post(
  "/api/dk-banner",
  verifyToken,
  upload.array("file"),
  async (req, res) => {
    try {
      const files = req.files || [];

      // multer + formData 특성상
      const normalizeToArray = (value) => {
        if (!value) return [];
        return Array.isArray(value) ? value : [value];
      };

      const file_name = normalizeToArray(req.body.file_name);
      const text = normalizeToArray(req.body.text);
      const text_detail = normalizeToArray(req.body.text_detail);
      const link = normalizeToArray(req.body.link);
      const file_url = normalizeToArray(req.body.file_url);
      const file_index = normalizeToArray(req.body.file_index); // 새 파일의 슬라이드 index

      // 필수값 체크
      if (!text.length || text.length !== link.length) {
        return res.status(400).json({ message: "데이터 형식 오류" });
      }
      if (!text_detail.length || text_detail.length !== link.length) {
        return res.status(400).json({ message: "데이터 형식 오류" });
      }

      // 🔥 기존 데이터 전체 삭제
      await pool.query("DELETE FROM dk_banners");

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
        INSERT INTO dk_banners (file_name, text, link, file_url, text_detail)
        VALUES (?, ?, ?, ?, ?)
        `,
          [file_name[i] || "", text[i], link[i], finalFileUrl, text_detail[i]],
        );
      }

      return res.json({ ok: true });
    } catch (err) {
      console.error("dk-banner save error:", err);
      return res.status(500).json({ message: "서버 오류" });
    }
  },
);

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
    const show_bn = normalizeToArray(req.body.show_bn);
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
        INSERT INTO main_room_banners (file_name, text, link, file_url, title, show_bn)
        VALUES (?, ?, ?, ?, ?, ?)
        `,
        [
          file_name[i] || "",
          text[i],
          link[i],
          finalFileUrl,
          title[i],
          show_bn[i],
        ],
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

app.get("/api/main-event-popup", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        id,
        title,
        width,
        height,
        file_url,
        file_name,
        link,
        sort_order,
        DATE_FORMAT(start_date, '%Y-%m-%d') AS start_date,
        DATE_FORMAT(end_date, '%Y-%m-%d') AS end_date
      FROM main_popup
      WHERE is_use = 1
        AND (
          start_date IS NULL
          OR start_date <= CURDATE()
        )
        AND (
          end_date IS NULL
          OR end_date >= CURDATE()
        )
      ORDER BY sort_order ASC, id ASC
    `);

    return res.json({
      ok: true,
      data: rows,
    });
  } catch (err) {
    console.error("client main-popup fetch error:", err);

    return res.status(500).json({
      ok: false,
      message: "이벤트 팝업 조회 중 오류가 발생했습니다.",
    });
  }
});
app.post("/api/main-event-popup", upload.array("file"), async (req, res) => {
  const conn = await pool.getConnection();

  const normalizeToArray = (value) => {
    if (value === undefined || value === null) return [];
    return Array.isArray(value) ? value : [value];
  };

  try {
    await conn.beginTransaction();

    const files = req.files || [];

    const title = normalizeToArray(req.body.title);
    const fileName = normalizeToArray(req.body.file_name);
    const width = normalizeToArray(req.body.width);
    const height = normalizeToArray(req.body.height);
    const link = normalizeToArray(req.body.link);
    const fileUrl = normalizeToArray(req.body.file_url);
    const isUse = normalizeToArray(req.body.is_use);
    const startDate = normalizeToArray(req.body.start_date);
    const endDate = normalizeToArray(req.body.end_date);
    const sortOrder = normalizeToArray(req.body.sort_order);
    const fileIndex = normalizeToArray(req.body.file_index);

    const rowCount = width.length;

    if (
      rowCount === 0 ||
      height.length !== rowCount ||
      link.length !== rowCount ||
      fileName.length !== rowCount ||
      fileUrl.length !== rowCount ||
      isUse.length !== rowCount ||
      startDate.length !== rowCount ||
      endDate.length !== rowCount ||
      sortOrder.length !== rowCount
    ) {
      await conn.rollback();

      return res.status(400).json({
        ok: false,
        message: "팝업 데이터 형식이 올바르지 않습니다.",
      });
    }

    /*
     * 업로드된 파일을 화면 행 index와 연결
     *
     * fileMap = {
     *   0: "/uploads/파일명.jpg",
     *   2: "/uploads/파일명2.jpg"
     * }
     */
    const fileMap = {};

    files.forEach((file, index) => {
      const rowIndex = Number(fileIndex[index]);

      if (Number.isInteger(rowIndex)) {
        fileMap[rowIndex] = `/uploads/${file.filename}`;
      }
    });

    const insertRows = [];

    for (let i = 0; i < rowCount; i++) {
      const popupWidth = Number(width[i]);
      const popupHeight = Number(height[i]);
      const popupIsUse = Number(isUse[i]) === 1 ? 1 : 0;
      const popupSortOrder = Number(sortOrder[i]) || i + 1;

      const popupStartDate = startDate[i] || null;
      const popupEndDate = endDate[i] || null;

      const finalFileUrl =
        fileMap[i] ||
        (fileUrl[i] && fileUrl[i].trim() !== "" ? fileUrl[i] : null);

      if (!finalFileUrl) {
        await conn.rollback();

        return res.status(400).json({
          ok: false,
          message: `${i + 1}번 팝업의 이미지가 누락되었습니다.`,
        });
      }

      if (!popupWidth || popupWidth <= 0) {
        await conn.rollback();

        return res.status(400).json({
          ok: false,
          message: `${i + 1}번 팝업의 너비를 확인해주세요.`,
        });
      }

      if (!popupHeight || popupHeight <= 0) {
        await conn.rollback();

        return res.status(400).json({
          ok: false,
          message: `${i + 1}번 팝업의 높이를 확인해주세요.`,
        });
      }

      if (!link[i] || !link[i].trim()) {
        await conn.rollback();

        return res.status(400).json({
          ok: false,
          message: `${i + 1}번 팝업의 링크를 입력해주세요.`,
        });
      }

      // 시작일과 종료일은 둘 다 입력하거나 둘 다 비워두기
      if (
        (popupStartDate && !popupEndDate) ||
        (!popupStartDate && popupEndDate)
      ) {
        await conn.rollback();

        return res.status(400).json({
          ok: false,
          message: `${i + 1}번 팝업의 게시 시작일과 종료일을 모두 입력해주세요.`,
        });
      }

      if (popupStartDate && popupEndDate && popupStartDate > popupEndDate) {
        await conn.rollback();

        return res.status(400).json({
          ok: false,
          message: `${i + 1}번 팝업의 게시 시작일이 종료일보다 늦습니다.`,
        });
      }

      insertRows.push([
        title[i] || "",
        fileName[i] || "",
        popupWidth,
        link[i],
        finalFileUrl,
        popupHeight,
        popupIsUse,
        popupStartDate,
        popupEndDate,
        popupSortOrder,
      ]);
    }

    // 모든 데이터 검증이 끝난 뒤 기존 데이터 삭제
    await conn.query("DELETE FROM main_popup");

    await conn.query(
      `
        INSERT INTO main_popup (
          title,
          file_name,
          width,
          link,
          file_url,
          height,
          is_use,
          start_date,
          end_date,
          sort_order
        )
        VALUES ?
        `,
      [insertRows],
    );

    await conn.commit();

    return res.json({
      ok: true,
      message: "메인 이벤트 팝업이 저장되었습니다.",
    });
  } catch (err) {
    await conn.rollback();

    console.error("main-popup save error:", err);

    return res.status(500).json({
      ok: false,
      message: "메인 이벤트 팝업 저장 중 서버 오류가 발생했습니다.",
    });
  } finally {
    conn.release();
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

app.get("/api/get-special-offer", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM special_offer ORDER BY id ASC`,
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

app.get("/api/get-ledger-ticket", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM ledger_ticket_bn ORDER BY id ASC`,
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

app.get("/api/get-around-and-spot", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM around_and_spot ORDER BY id ASC`,
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

app.get("/api/get-dk-banner", async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT * FROM dk_banners ORDER BY id ASC`);

    return res.json({
      ok: true,
      data: rows,
    });
  } catch (err) {
    console.error("dk_banners fetch error:", err);
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
app.get("/api/get-main-event-popup", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        id,
        title,
        width,
        height,
        file_url,
        file_name,
        link,
        is_use,
        sort_order,
        DATE_FORMAT(start_date, '%Y-%m-%d') AS start_date,
        DATE_FORMAT(end_date, '%Y-%m-%d') AS end_date
      FROM main_popup
      ORDER BY sort_order ASC, id ASC
    `);

    return res.json({
      ok: true,
      data: rows,
    });
  } catch (err) {
    console.error("main_popup fetch error:", err);

    return res.status(500).json({
      ok: false,
      message: "메인 이벤트 팝업 조회 중 오류가 발생했습니다.",
    });
  }
});

app.post("/api/room-price", async (req, res) => {
  const conn = await pool.getConnection();
  console.log("room-price body:", req.body);
  try {
    const { dates, rooms, checkedIds } = req.body;

    if (!Array.isArray(dates) || dates.length === 0) {
      return res.status(400).json({
        ok: false,
        message: "저장할 날짜 데이터가 없습니다.",
      });
    }

    if (!Array.isArray(rooms)) {
      return res.status(400).json({
        ok: false,
        message: "저장할 객실 데이터가 없습니다.",
      });
    }

    if (!Array.isArray(checkedIds)) {
      return res.status(400).json({
        ok: false,
        message: "체크된 객실 데이터가 없습니다.",
      });
    }

    await conn.beginTransaction();

    // 체크가 하나도 없으면 해당 날짜 전체 삭제
    if (checkedIds.length === 0) {
      await conn.query(
        `
        DELETE FROM room_price
        WHERE date IN (?)
        `,
        [dates],
      );
    } else {
      // 체크 해제된 객실만 삭제
      await conn.query(
        `
        DELETE FROM room_price
        WHERE date IN (?)
        AND room_group_id NOT IN (?)
        `,
        [dates, checkedIds],
      );
    }

    // 체크된 객실 가격 저장 / 수정
    if (rooms.length > 0) {
      const values = [];

      dates.forEach((date) => {
        rooms.forEach((room) => {
          values.push([
            date,
            room.room_group_id,
            room.room_group_name,
            Number(room.price || 0),
            Number(room.day_use_price || 0),
            Number(room.human_plus_price || 0),
            Number(room.pet_plus_price || 0),
            Number(room.is_day_use ?? 1),
          ]);
        });
      });

      await conn.query(
        `
        INSERT INTO room_price
        (
          date,
          room_group_id,
          room_group_name,
          price,
          day_use_price,
          human_plus_price,
          pet_plus_price,
          is_day_use
        )
        VALUES ?
        ON DUPLICATE KEY UPDATE
          room_group_name = VALUES(room_group_name),
          price = VALUES(price),
          day_use_price = VALUES(day_use_price),
          human_plus_price = VALUES(human_plus_price),
          pet_plus_price = VALUES(pet_plus_price),
          is_day_use = VALUES(is_day_use)
        `,
        [values],
      );
    }

    await conn.commit();

    return res.json({
      ok: true,
      message: "객실 가격이 저장되었습니다.",
    });
  } catch (error) {
    await conn.rollback();

    console.error("room_price save error:", error);

    return res.status(500).json({
      ok: false,
      message: "객실 가격 저장 중 오류 발생",
    });
  } finally {
    conn.release();
  }
});
app.get("/api/room-price", async (req, res) => {
  try {
    let { year, month, roomId } = req.query;

    let query = `
      SELECT
        id,
        room_group_id,
        room_group_name,
        price,
        day_use_price,
        human_plus_price,
        pet_plus_price,
        is_day_use,
        DATE_FORMAT(date, '%Y-%m-%d') AS date
      FROM room_price
      WHERE 1=1
    `;

    const params = [];

    // year, month가 넘어온 경우에만 월 조건 추가
    if (year && month) {
      month = String(month).padStart(2, "0");

      const startDate = `${year}-${month}-01`;

      const nextMonthDate = new Date(Number(year), Number(month), 1);
      const nextYear = nextMonthDate.getFullYear();
      const nextMonthStr = String(nextMonthDate.getMonth() + 1).padStart(
        2,
        "0",
      );
      const endDate = `${nextYear}-${nextMonthStr}-01`;

      query += `
        AND date >= ?
        AND date < ?
      `;

      params.push(startDate, endDate);
    }

    // room_group_id 조건
    if (roomId !== undefined && roomId !== null && roomId !== "") {
      const parsedRoomId = Number(roomId);

      if (!isNaN(parsedRoomId)) {
        query += ` AND room_group_id = ?`;
        params.push(parsedRoomId);
      }
    }

    query += ` ORDER BY date ASC, room_group_id ASC`;

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

app.patch("/api/room-price/day-use", async (req, res) => {
  try {
    const { dates, room_group_ids, is_day_use } = req.body;

    if (!Array.isArray(dates) || dates.length === 0) {
      return res.status(400).json({
        ok: false,
        message: "변경할 날짜가 없습니다.",
      });
    }

    if (!Array.isArray(room_group_ids) || room_group_ids.length === 0) {
      return res.status(400).json({
        ok: false,
        message: "변경할 객실이 없습니다.",
      });
    }

    const parsedIsDayUse = Number(is_day_use);

    if (![0, 1, 2].includes(parsedIsDayUse)) {
      return res.status(400).json({
        ok: false,
        message: "is_day_use 값이 올바르지 않습니다.",
      });
    }

    await pool.query(
      `
      UPDATE room_price
      SET is_day_use = ?
      WHERE date IN (?)
      AND room_group_id IN (?)
      `,
      [parsedIsDayUse, dates, room_group_ids],
    );

    return res.json({
      ok: true,
      message: "가능 유형이 변경되었습니다.",
    });
  } catch (error) {
    console.error("room_price day_use update error:", error);

    return res.status(500).json({
      ok: false,
      message: "가능 유형 변경 중 오류 발생",
    });
  }
});

// app.put("/api/room/:id", verifyToken, async (req, res) => {
//   try {
//     const { id } = req.params;

//     const {
//       name,
//       is_active,
//       reason,
//       capacity_max,
//       capacity_min,
//       day_use,
//       disable_start,
//       disable_end,
//       manual_booking,
//       cancel_booking,
//       soogie,
//     } = req.body;

//     // =================================================
//     // 1️⃣ 필수값 체크
//     // =================================================
//     if (
//       !name ||
//       typeof is_active === "undefined" ||
//       capacity_max === undefined ||
//       capacity_min === undefined ||
//       day_use === undefined
//     ) {
//       return res.status(400).json({
//         ok: false,
//         message:
//           "name, is_active, capacity_max, capacity_min, day_use는 필수입니다.",
//       });
//     }

//     const numericMax = Number(capacity_max);
//     const numericMin = Number(capacity_min);
//     const numericDayUse = Number(day_use);

//     if (isNaN(numericMax) || isNaN(numericMin) || numericMax < numericMin) {
//       return res.status(400).json({
//         ok: false,
//         message: "capacity 값이 올바르지 않습니다.",
//       });
//     }

//     if (![0, 1, 2].includes(numericDayUse)) {
//       return res.status(400).json({
//         ok: false,
//         message: "day_use는 0, 1, 2 중 하나여야 합니다.",
//       });
//     }

//     // =================================================
//     // 2️⃣ 예약 타입 계산
//     // 0 = 숙박만
//     // 1 = 데이+숙박
//     // 2 = 데이만
//     // =================================================
//     let finalDayUse = 0;
//     let lodgement = 0;

//     if (numericDayUse === 0) {
//       finalDayUse = 0;
//       lodgement = 1;
//     } else if (numericDayUse === 1) {
//       finalDayUse = 1;
//       lodgement = 1;
//     } else if (numericDayUse === 2) {
//       finalDayUse = 2;
//       lodgement = 0;
//     }

//     // =================================================
//     // 3️⃣ 비활성화 체크
//     // =================================================
//     if (Number(is_active) === 0) {
//       if (!reason || reason.trim() === "") {
//         return res.status(400).json({
//           ok: false,
//           message: "비활성화 시 사유는 필수입니다.",
//         });
//       }

//       if (!disable_start || !disable_end) {
//         return res.status(400).json({
//           ok: false,
//           message: "비활성 기간은 필수입니다.",
//         });
//       }

//       if (disable_start > disable_end) {
//         return res.status(400).json({
//           ok: false,
//           message: "시작일은 종료일보다 클 수 없습니다.",
//         });
//       }
//     }

//     // =================================================
//     // 4️⃣ 기존 데이터 조회
//     // =================================================
//     const [roomRows] = await pool.query(
//       `SELECT room_group_id, is_ota, check_in_and_out_soogie
//        FROM room
//        WHERE id = ?`,
//       [id],
//     );

//     if (roomRows.length === 0) {
//       return res.status(404).json({
//         ok: false,
//         message: "해당 객실을 찾을 수 없습니다.",
//       });
//     }

//     const roomGroupId = roomRows[0].room_group_id;
//     const currentIsOta = roomRows[0].is_ota;

//     // =================================================
//     // 5️⃣ 수기예약 JSON 파싱
//     // =================================================
//     let finalSoogieSchedule = [];

//     try {
//       finalSoogieSchedule = roomRows[0].check_in_and_out_soogie
//         ? JSON.parse(roomRows[0].check_in_and_out_soogie)
//         : [];
//     } catch {
//       finalSoogieSchedule = [];
//     }

//     // =================================================
//     // 6️⃣ 수기예약 추가
//     // =================================================
//     if (manual_booking && Number(is_active) === 0) {
//       finalSoogieSchedule.push(manual_booking);
//     }

//     // =================================================
//     // 7️⃣ 수기예약 취소
//     // =================================================
//     if (cancel_booking) {
//       finalSoogieSchedule = finalSoogieSchedule.filter((b) => {
//         return !(
//           b.check_in === cancel_booking.check_in &&
//           b.check_out === cancel_booking.check_out
//         );
//       });
//     }

//     // =================================================
//     // 8️⃣ 상태 계산
//     // =================================================
//     const finalReason = Number(is_active) === 1 ? null : reason?.trim();
//     const finalStart = Number(is_active) === 1 ? null : disable_start;
//     const finalEnd = Number(is_active) === 1 ? null : disable_end;

//     const finalCheckIn = finalStart;
//     const finalCheckOut = finalEnd;
//     const finalSoogie = finalSoogieSchedule.length > 0 ? 1 : 0;
//     const finalSoogieText =
//       finalSoogieSchedule.length > 0 ? soogie || null : null;
//     const finalIsActive =
//       finalSoogieSchedule.length > 0 ? 0 : Number(is_active);

//     const finalIsOta = finalSoogie === 1 ? 0 : currentIsOta;

//     // =================================================
//     // 9️⃣ 그룹 전체 옵션 업데이트
//     // =================================================
//     await pool.query(
//       `
//       UPDATE room
//       SET capacity_max = ?,
//           capacity_min = ?,
//           day_use = ?,
//           lodgement = ?
//       WHERE room_group_id = ?
//       `,
//       [numericMax, numericMin, finalDayUse, lodgement, roomGroupId],
//     );

//     // =================================================
//     // 🔟 개별 room 업데이트
//     // =================================================
//     await pool.query(
//       `
//       UPDATE room
//       SET name = ?,
//           is_active = ?,
//           reason = ?,
//           disable_start = ?,
//           disable_end = ?,
//           check_in = ?,
//           check_out = ?,
//           is_soogie = ?,
//           is_ota = ?,
//           check_in_and_out_soogie = ?,
//           soogie = ?
//       WHERE id = ?
//       `,
//       [
//         name.trim(),
//         finalIsActive,
//         finalReason,
//         finalStart,
//         finalEnd,
//         finalCheckIn,
//         finalCheckOut,
//         finalSoogie,
//         finalIsOta,
//         JSON.stringify(finalSoogieSchedule),
//         finalSoogieText || null,
//         id,
//       ],
//     );

//     return res.json({
//       ok: true,
//       message: "객실 정보 수정 완료",
//     });
//   } catch (error) {
//     console.error("room update error:", error);
//     return res.status(500).json({
//       ok: false,
//       message: "객실 수정 중 오류 발생",
//     });
//   }
// });

app.put("/api/room/:id", verifyToken, async (req, res) => {
  const conn = await pool.getConnection();

  const parseSchedule = (value) => {
    if (!value) return [];

    if (Array.isArray(value)) {
      return value;
    }

    if (typeof value === "string") {
      try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    }

    return [];
  };

  const normalizeDate = (value) => {
    if (!value) return "";
    return String(value).slice(0, 10);
  };

  const isSameBooking = (a, b) => {
    return (
      normalizeDate(a.check_in) === normalizeDate(b.check_in) &&
      normalizeDate(a.check_out) === normalizeDate(b.check_out) &&
      String(a.source || "manual") === String(b.source || "manual")
    );
  };

  try {
    await conn.beginTransaction();

    const { id } = req.params;

    // EXTRA_로 시작하면 extra_room
    const isExtra = String(id).startsWith("EXTRA_");

    const {
      name,
      is_active,
      reason,
      disable_start,
      disable_end,
      start_date,
      end_date,

      capacity_max,
      capacity_min,

      capacity_max_dayuse,
      capacity_min_dayuse,

      day_use,
      is_pet,

      manual_booking,
      cancel_booking,
      soogie,
    } = req.body;

    // =====================================================
    // 필수값 검증
    // =====================================================
    if (
      !name?.trim() ||
      typeof is_active === "undefined" ||
      capacity_max === undefined ||
      capacity_min === undefined ||
      capacity_max_dayuse === undefined ||
      capacity_min_dayuse === undefined ||
      day_use === undefined ||
      is_pet === undefined
    ) {
      await conn.rollback();

      return res.status(400).json({
        ok: false,
        message:
          "name, is_active, capacity_max, capacity_min, capacity_max_dayuse, capacity_min_dayuse, day_use, is_pet는 필수입니다.",
      });
    }

    const numericMax = Number(capacity_max);
    const numericMin = Number(capacity_min);

    const numericMaxDayuse = Number(capacity_max_dayuse);
    const numericMinDayuse = Number(capacity_min_dayuse);

    const numericDayUse = Number(day_use);
    const numericIsPet = Number(is_pet);

    // =====================================================
    // 숙박 인원 검증
    // =====================================================
    if (
      Number.isNaN(numericMax) ||
      Number.isNaN(numericMin) ||
      numericMin < 0 ||
      numericMax < 0 ||
      numericMax < numericMin
    ) {
      await conn.rollback();

      return res.status(400).json({
        ok: false,
        message: "capacity 값이 올바르지 않습니다.",
      });
    }

    // =====================================================
    // 데이유즈 인원 검증
    // =====================================================
    if (
      Number.isNaN(numericMaxDayuse) ||
      Number.isNaN(numericMinDayuse) ||
      numericMinDayuse < 0 ||
      numericMaxDayuse < 0 ||
      numericMaxDayuse < numericMinDayuse
    ) {
      await conn.rollback();

      return res.status(400).json({
        ok: false,
        message: "데이유즈 capacity 값이 올바르지 않습니다.",
      });
    }

    // =====================================================
    // day_use 검증
    // =====================================================
    if (![0, 1, 2].includes(numericDayUse)) {
      await conn.rollback();

      return res.status(400).json({
        ok: false,
        message: "day_use는 0, 1, 2 중 하나여야 합니다.",
      });
    }

    // =====================================================
    // 반려동물 수용 여부 검증
    // 0 = 불가능
    // 1 = 가능
    // =====================================================
    if (![0, 1].includes(numericIsPet)) {
      await conn.rollback();

      return res.status(400).json({
        ok: false,
        message: "is_pet은 0 또는 1이어야 합니다.",
      });
    }

    // =====================================================
    // 임시 객실 기간 검증
    // =====================================================
    if (isExtra) {
      if (!start_date || !end_date) {
        await conn.rollback();

        return res.status(400).json({
          ok: false,
          message: "임시 객실의 시작일과 종료일은 필수입니다.",
        });
      }

      if (normalizeDate(start_date) > normalizeDate(end_date)) {
        await conn.rollback();

        return res.status(400).json({
          ok: false,
          message: "시작일은 종료일보다 클 수 없습니다.",
        });
      }
    }

    // =====================================================
    // day_use / lodgement 계산
    // =====================================================
    let finalDayUse = 0;
    let lodgement = 0;

    if (numericDayUse === 0) {
      finalDayUse = 0;
      lodgement = 1;
    } else if (numericDayUse === 1) {
      finalDayUse = 1;
      lodgement = 1;
    } else {
      finalDayUse = 2;
      lodgement = 0;
    }

    // =====================================================
    // 대상 객실 조회
    // =====================================================
    let roomRows;

    if (isExtra) {
      [roomRows] = await conn.query(
        `
        SELECT
          id,
          extra_id,
          room_group_id,
          is_ota,
          check_in_and_out_soogie
        FROM extra_room
        WHERE extra_id = ?
        FOR UPDATE
        `,
        [id],
      );
    } else {
      [roomRows] = await conn.query(
        `
        SELECT
          id,
          room_group_id,
          is_ota,
          check_in_and_out_soogie
        FROM room
        WHERE id = ?
        FOR UPDATE
        `,
        [id],
      );
    }

    if (roomRows.length === 0) {
      await conn.rollback();

      return res.status(404).json({
        ok: false,
        message: isExtra
          ? "해당 임시 객실을 찾을 수 없습니다."
          : "해당 객실을 찾을 수 없습니다.",
      });
    }

    const currentRoom = roomRows[0];
    const roomGroupId = currentRoom.room_group_id;
    const currentIsOta = currentRoom.is_ota;

    let finalSoogieSchedule = parseSchedule(
      currentRoom.check_in_and_out_soogie,
    );

    // =====================================================
    // 수기예약 취소
    // =====================================================
    if (cancel_booking) {
      const cancelCheckIn = normalizeDate(cancel_booking.check_in);
      const cancelCheckOut = normalizeDate(cancel_booking.check_out);

      finalSoogieSchedule = finalSoogieSchedule.filter((booking) => {
        return !isSameBooking(booking, cancel_booking);
      });

      if (!isExtra) {
        await conn.query(
          `
          UPDATE room_booking_history
          SET canceled = 1
          WHERE room_id = ?
            AND source = 'manual'
            AND check_in = ?
            AND check_out = ?
            AND canceled = 0
          `,
          [id, cancelCheckIn, cancelCheckOut],
        );
      }
    }

    // =====================================================
    // 수기예약 추가
    // =====================================================
    if (manual_booking) {
      const newManualBooking = {
        ...manual_booking,
        source: manual_booking.source || "manual",
        check_in: normalizeDate(manual_booking.check_in),
        check_out: normalizeDate(manual_booking.check_out),
      };

      const duplicated = finalSoogieSchedule.some((booking) =>
        isSameBooking(booking, newManualBooking),
      );

      if (!duplicated) {
        finalSoogieSchedule.push(newManualBooking);
      }
    }

    finalSoogieSchedule.sort((a, b) => {
      return normalizeDate(a.check_in).localeCompare(normalizeDate(b.check_in));
    });

    const finalSoogie = finalSoogieSchedule.length > 0 ? 1 : 0;
    const finalSoogieText = finalSoogie ? soogie || null : null;

    const finalIsActive = finalSoogie ? 0 : Number(is_active);
    const finalIsOta = finalSoogie ? 0 : currentIsOta;

    const finalReason = finalSoogie
      ? "수기예약"
      : Number(is_active) === 1
        ? null
        : reason?.trim() || null;

    // =====================================================
    // 동일 그룹의 일반 객실 일괄 갱신
    // =====================================================
    await conn.query(
      `
      UPDATE room
      SET
        capacity_max = ?,
        capacity_min = ?,
        capacity_max_dayuse = ?,
        capacity_min_dayuse = ?,
        day_use = ?,
        lodgement = ?,
        is_pet = ?
      WHERE room_group_id = ?
      `,
      [
        numericMax,
        numericMin,
        numericMaxDayuse,
        numericMinDayuse,
        finalDayUse,
        lodgement,
        numericIsPet,
        roomGroupId,
      ],
    );

    // =====================================================
    // 동일 그룹의 임시 객실 일괄 갱신
    // =====================================================
    await conn.query(
      `
      UPDATE extra_room
      SET
        capacity_max = ?,
        capacity_min = ?,
        capacity_max_dayuse = ?,
        capacity_min_dayuse = ?,
        day_use = ?,
        lodgement = ?,
        is_pet = ?
      WHERE room_group_id = ?
      `,
      [
        numericMax,
        numericMin,
        numericMaxDayuse,
        numericMinDayuse,
        finalDayUse,
        lodgement,
        numericIsPet,
        roomGroupId,
      ],
    );

    // =====================================================
    // 선택한 개별 객실 정보 수정
    // =====================================================
    if (isExtra) {
      await conn.query(
        `
        UPDATE extra_room
        SET
          name = ?,
          is_active = ?,
          reason = ?,
          start_date = ?,
          end_date = ?,
          disable_start = NULL,
          disable_end = NULL,
          check_in = NULL,
          check_out = NULL,
          is_soogie = ?,
          is_ota = ?,
          check_in_and_out_soogie = ?,
          soogie = ?
        WHERE extra_id = ?
        `,
        [
          name.trim(),
          finalIsActive,
          finalReason,
          normalizeDate(start_date),
          normalizeDate(end_date),
          finalSoogie,
          finalIsOta,
          JSON.stringify(finalSoogieSchedule),
          finalSoogieText,
          id,
        ],
      );
    } else {
      await conn.query(
        `
        UPDATE room
        SET
          name = ?,
          is_active = ?,
          reason = ?,
          disable_start = ?,
          disable_end = ?,
          check_in = NULL,
          check_out = NULL,
          is_soogie = ?,
          is_ota = ?,
          check_in_and_out_soogie = ?,
          soogie = ?
        WHERE id = ?
        `,
        [
          name.trim(),
          finalIsActive,
          finalReason,

          Number(is_active) === 1 ? null : normalizeDate(disable_start) || null,

          Number(is_active) === 1 ? null : normalizeDate(disable_end) || null,

          finalSoogie,
          finalIsOta,
          JSON.stringify(finalSoogieSchedule),
          finalSoogieText,
          id,
        ],
      );
    }

    await conn.commit();

    return res.json({
      ok: true,
      message: isExtra ? "임시 객실 정보 수정 완료" : "객실 정보 수정 완료",
      room_type: isExtra ? "extra" : "normal",
      schedules: finalSoogieSchedule,
    });
  } catch (error) {
    await conn.rollback();

    console.error("room update error:", error);

    return res.status(500).json({
      ok: false,
      message: "객실 수정 중 오류 발생",
    });
  } finally {
    conn.release();
  }
});
app.put("/api/room-group/:id", verifyToken, async (req, res) => {
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const { id } = req.params;

    const { name, is_active, reason, unused_option_ids, contract_txt } =
      req.body;

    const numericId = Number(id);

    // 1. 그룹 ID 검사
    if (!Number.isInteger(numericId) || numericId <= 0) {
      await connection.rollback();

      return res.status(400).json({
        ok: false,
        message: "객실 그룹 ID가 올바르지 않습니다.",
      });
    }

    // 2. 기본값 검사
    if (typeof name !== "string" || !name.trim()) {
      await connection.rollback();

      return res.status(400).json({
        ok: false,
        message: "그룹명은 필수입니다.",
      });
    }

    if (typeof is_active === "undefined") {
      await connection.rollback();

      return res.status(400).json({
        ok: false,
        message: "is_active는 필수입니다.",
      });
    }

    const numericIsActive = Number(is_active);

    if (![0, 1].includes(numericIsActive)) {
      await connection.rollback();

      return res.status(400).json({
        ok: false,
        message: "is_active 값이 올바르지 않습니다.",
      });
    }

    if (
      numericIsActive === 0 &&
      (typeof reason !== "string" || !reason.trim())
    ) {
      await connection.rollback();

      return res.status(400).json({
        ok: false,
        message: "비활성화 시 사유를 입력해주세요.",
      });
    }

    // 3. unused_option_ids 정리
    let parsedUnusedOptionIds = unused_option_ids;

    if (
      typeof parsedUnusedOptionIds === "undefined" ||
      parsedUnusedOptionIds === null ||
      parsedUnusedOptionIds === ""
    ) {
      parsedUnusedOptionIds = [];
    }

    if (typeof parsedUnusedOptionIds === "string") {
      try {
        parsedUnusedOptionIds = JSON.parse(parsedUnusedOptionIds);
      } catch {
        await connection.rollback();

        return res.status(400).json({
          ok: false,
          message: "unused_option_ids 형식이 올바르지 않습니다.",
        });
      }
    }

    if (!Array.isArray(parsedUnusedOptionIds)) {
      await connection.rollback();

      return res.status(400).json({
        ok: false,
        message: "unused_option_ids는 배열이어야 합니다.",
      });
    }

    const finalUnusedOptionIds = [
      ...new Set(
        parsedUnusedOptionIds
          .map((optionId) => Number(optionId))
          .filter((optionId) => Number.isInteger(optionId) && optionId > 0),
      ),
    ];

    // 4. contract_txt 정리
    // 프론트에서 JSON.stringify()한 문자열로 전송됨
    let parsedContractSections = contract_txt;

    if (
      typeof parsedContractSections === "undefined" ||
      parsedContractSections === null ||
      parsedContractSections === ""
    ) {
      parsedContractSections = [];
    }

    if (typeof parsedContractSections === "string") {
      try {
        parsedContractSections = JSON.parse(parsedContractSections);
      } catch {
        await connection.rollback();

        return res.status(400).json({
          ok: false,
          message: "안내사항 JSON 형식이 올바르지 않습니다.",
        });
      }
    }

    if (!Array.isArray(parsedContractSections)) {
      await connection.rollback();

      return res.status(400).json({
        ok: false,
        message: "안내사항 데이터는 배열이어야 합니다.",
      });
    }

    // 5. contract_txt 내부 데이터 정리
    const finalContractSections = parsedContractSections
      .map((section) => {
        if (!section || typeof section !== "object" || Array.isArray(section)) {
          return null;
        }

        const type = ["section", "star", "privacy"].includes(section.type)
          ? section.type
          : "section";

        const title = String(section.title || "").trim();
        const intro = String(section.intro || "").trim();

        const items = Array.isArray(section.items)
          ? section.items
              .map((item) => String(item || "").trim())
              .filter(Boolean)
          : [];

        if (type === "star") {
          return {
            type: "star",
            items,
          };
        }

        if (type === "privacy") {
          return {
            type: "privacy",
            title,
            intro,
            items,
          };
        }

        return {
          type: "section",
          title,
          items,
        };
      })
      .filter(
        (section) =>
          section &&
          (section.title || section.intro || section.items.length > 0),
      );

    const finalName = name.trim();

    const finalReason = numericIsActive === 1 ? null : reason.trim();

    // JSON 컬럼에 넣을 유효한 JSON 문자열
    const finalUnusedOptionIdsJson = JSON.stringify(finalUnusedOptionIds);

    const finalContractTxtJson = JSON.stringify(finalContractSections);

    // 6. room_group 수정
    const [result] = await connection.query(
      `
      UPDATE room_group
      SET
        name = ?,
        is_active = ?,
        reason = ?,
        unused_option_ids = ?,
        contract_txt = ?
      WHERE id = ?
      `,
      [
        finalName,
        numericIsActive,
        finalReason,
        finalUnusedOptionIdsJson,
        finalContractTxtJson,
        numericId,
      ],
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
      message: "객실 그룹 수정 완료",
      data: {
        id: numericId,
        name: finalName,
        is_active: numericIsActive,
        reason: finalReason,
        unused_option_ids: finalUnusedOptionIds,
        contract_txt: finalContractSections,
      },
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
app.post("/api/room/:id/manual-booking", verifyToken, async (req, res) => {
  const conn = await pool.getConnection();

  const parseSchedule = (value) => {
    if (!value) return [];

    if (Array.isArray(value)) return value;

    if (typeof value === "string") {
      try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    }

    return [];
  };

  try {
    await conn.beginTransaction();

    const { id } = req.params;
    const { manual_booking } = req.body;

    const isExtra = String(id).startsWith("EXTRA_");

    if (!manual_booking?.check_in || !manual_booking?.check_out) {
      await conn.rollback();

      return res.status(400).json({
        ok: false,
        message: "check_in, check_out 필수",
      });
    }

    // 1. 먼저 객실 정보와 기존 수기예약 목록을 조회한다.
    const [rows] = isExtra
      ? await conn.query(
          `
          SELECT
            extra_id AS id,
            room_group_id,
            check_in_and_out_soogie
          FROM extra_room
          WHERE extra_id = ?
          FOR UPDATE
          `,
          [id],
        )
      : await conn.query(
          `
          SELECT
            id,
            room_group_id,
            check_in_and_out_soogie
          FROM room
          WHERE id = ?
          FOR UPDATE
          `,
          [id],
        );

    if (!rows.length) {
      await conn.rollback();

      return res.status(404).json({
        ok: false,
        message: "객실 없음",
      });
    }

    // 2. 조회된 기존 수기예약 데이터를 배열로 변환한다.
    const schedules = parseSchedule(rows[0].check_in_and_out_soogie);

    const newBooking = {
      source: "manual",
      check_in: String(manual_booking.check_in).slice(0, 10),
      check_out: String(manual_booking.check_out).slice(0, 10),
      memo: manual_booking.memo || "",

      custom_room_no: Array.isArray(manual_booking.custom_room_no)
        ? manual_booking.custom_room_no
        : manual_booking.custom_room_no
          ? [manual_booking.custom_room_no]
          : [],

      custom_name: manual_booking.custom_name || "",
    };

    // 3. 같은 체크인/체크아웃의 수기예약 중복 여부 확인
    const duplicated = schedules.some((booking) => {
      return (
        String(booking?.source || "manual") === "manual" &&
        String(booking?.check_in || "").slice(0, 10) === newBooking.check_in &&
        String(booking?.check_out || "").slice(0, 10) === newBooking.check_out
      );
    });

    if (duplicated) {
      await conn.rollback();

      return res.status(409).json({
        ok: false,
        message: "동일 기간의 수기예약이 이미 존재합니다.",
      });
    }

    schedules.push(newBooking);

    schedules.sort((a, b) =>
      String(a?.check_in || "").localeCompare(String(b?.check_in || "")),
    );

    // 4. 최종 schedules를 객실 테이블에 한 번만 저장한다.
    if (isExtra) {
      await conn.query(
        `
        UPDATE extra_room
        SET
          check_in_and_out_soogie = ?,
          is_soogie = 1,
          is_active = 0,
          is_ota = 0,
          reason = '수기예약'
        WHERE extra_id = ?
        `,
        [JSON.stringify(schedules), id],
      );
    } else {
      await conn.query(
        `
        UPDATE room
        SET
          check_in_and_out_soogie = ?,
          is_soogie = 1,
          is_active = 0,
          is_ota = 0,
          reason = '수기예약'
        WHERE id = ?
        `,
        [JSON.stringify(schedules), id],
      );
    }

    // 5. 예약 히스토리 기록
    const manualBookingId =
      `MANUAL_${id}_${newBooking.check_in}_` +
      `${newBooking.check_out}_${Date.now()}`;

    const payload = {
      booking_id: manualBookingId,
      product_name: "수기예약",

      name: newBooking.custom_name || "",
      phone: "",

      price: 0,
      qty: 1,

      booking_option: null,
      request_memo: newBooking.memo || "",

      custom_room_no: newBooking.custom_room_no || [],
      custom_name: newBooking.custom_name || "",

      check_in: newBooking.check_in,
      check_out: newBooking.check_out,
    };

    await conn.query(
      `
      INSERT INTO room_booking_history (
        payload,
        booking_id,
        check_in,
        check_out,
        room_id,
        room_group_id,
        source,
        guest_name,
        guest_phone,
        qty,
        price,
        product_name,
        memo,
        canceled
      )
      VALUES (?, ?, ?, ?, ?, ?, 'manual', ?, '', 1, 0, '수기예약', ?, 0)
      `,
      [
        JSON.stringify(payload),
        manualBookingId,
        newBooking.check_in,
        newBooking.check_out,
        String(id),
        rows[0].room_group_id,
        newBooking.custom_name || "",
        newBooking.memo || "",
      ],
    );

    await conn.commit();

    return res.json({
      ok: true,
      message: "수기예약 추가 완료",
      schedules,
    });
  } catch (err) {
    await conn.rollback();

    console.error("manual booking append error:", err);

    return res.status(500).json({
      ok: false,
      message: "수기예약 추가 실패",
      error: err.message,
    });
  } finally {
    conn.release();
  }
});
app.delete("/api/extra-room/:extraId", async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();

    const { extraId } = req.params;

    const [result] = await conn.query(
      `
      DELETE FROM extra_room
      WHERE extra_id = ?
      `,
      [extraId],
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: "삭제할 임시 객실을 찾을 수 없습니다.",
      });
    }

    res.json({
      success: true,
      message: "임시 객실이 삭제되었습니다.",
    });
  } catch (error) {
    console.error("임시 객실 삭제 오류:", error);

    res.status(500).json({
      success: false,
      message: "임시 객실 삭제 중 오류가 발생했습니다.",
    });
  } finally {
    if (conn) conn.release();
    syncNaverBookingsToRooms();
  }
});

app.put("/api/rooms/bulk-update", verifyToken, async (req, res) => {
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const { ids, is_active, reason, disable_start, disable_end } = req.body;

    // 🔹 기본 검증
    if (!Array.isArray(ids) || ids.length === 0) {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        message: "ids 배열이 필요합니다.",
      });
    }

    if (typeof is_active === "undefined") {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        message: "is_active는 필수입니다.",
      });
    }

    // 🔹 비활성화 시 조건
    if (Number(is_active) === 0) {
      if (!reason || reason.trim() === "") {
        await connection.rollback();
        return res.status(400).json({
          ok: false,
          message: "비활성화 시 사유는 필수입니다.",
        });
      }

      if (!disable_start || !disable_end) {
        await connection.rollback();
        return res.status(400).json({
          ok: false,
          message: "비활성 기간은 필수입니다.",
        });
      }
    }

    const finalReason = Number(is_active) === 1 ? null : reason.trim();

    const finalStart = Number(is_active) === 1 ? null : disable_start;

    const finalEnd = Number(is_active) === 1 ? null : disable_end;

    // 🔹 IN 절용 placeholder 생성
    const placeholders = ids.map(() => "?").join(",");

    // 🔥 핵심 쿼리
    const [result] = await connection.query(
      `
      UPDATE room
      SET 
        is_active = ?,
        reason = ?,
        disable_start = ?,
        disable_end = ?,
        is_soogie = 1
      WHERE id IN (${placeholders})
      `,
      [Number(is_active), finalReason, finalStart, finalEnd, ...ids],
    );

    await connection.commit();

    return res.json({
      ok: true,
      message: `${result.affectedRows}개 객실 수정 완료`,
    });
  } catch (error) {
    await connection.rollback();
    console.error("bulk room update error:", error);
    return res.status(500).json({
      ok: false,
      message: "객실 일괄 수정 중 오류 발생",
    });
  } finally {
    connection.release();
  }
});

// app.delete("/api/room/:id", verifyToken, async (req, res) => {
//   try {
//     const { id } = req.params;

//     const [result] = await pool.query(`DELETE FROM room WHERE id = ?`, [id]);

//     if (result.affectedRows === 0) {
//       return res.status(404).json({
//         ok: false,
//         message: "해당 객실을 찾을 수 없습니다.",
//       });
//     }

//     return res.json({
//       ok: true,
//       message: "객실 삭제 완료",
//     });
//   } catch (error) {
//     console.error("room delete error:", error);
//     return res.status(500).json({
//       ok: false,
//       message: "객실 삭제 중 오류 발생",
//     });
//   }
// });

app.delete("/api/room/:id", verifyToken, async (req, res) => {
  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    const { id } = req.params;

    const [roomRows] = await conn.query(
      `
      SELECT id
      FROM room
      WHERE id = ?
      FOR UPDATE
      `,
      [id],
    );

    if (roomRows.length === 0) {
      await conn.rollback();

      return res.status(404).json({
        ok: false,
        message: "해당 객실을 찾을 수 없습니다.",
      });
    }

    const [result] = await conn.query(
      `
      DELETE FROM room
      WHERE id = ?
      `,
      [id],
    );

    await conn.commit();

    return res.json({
      ok: true,
      message: "객실 삭제 완료",
      affectedRows: result.affectedRows,
    });
  } catch (error) {
    await conn.rollback();
    console.error("room delete error:", error);

    return res.status(500).json({
      ok: false,
      message: "객실 삭제 중 오류 발생",
    });
  } finally {
    conn.release();
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

      capacity_min,
      capacity_max,

      capacity_min_dayuse,
      capacity_max_dayuse,

      day_use,
      is_pet,
    } = req.body;

    // =================================================
    // 1. 필수값 체크
    // =================================================
    if (
      !name?.trim() ||
      room_group_id === undefined ||
      room_group_id === null ||
      room_group_id === "" ||
      capacity_min === undefined ||
      capacity_max === undefined ||
      capacity_min_dayuse === undefined ||
      capacity_max_dayuse === undefined ||
      day_use === undefined ||
      is_pet === undefined
    ) {
      return res.status(400).json({
        ok: false,
        message:
          "name, room_group_id, capacity_min, capacity_max, capacity_min_dayuse, capacity_max_dayuse, day_use, is_pet는 필수입니다.",
      });
    }

    const numericRoomGroupId = Number(room_group_id);

    const numericMin = Number(capacity_min);
    const numericMax = Number(capacity_max);

    const numericMinDayuse = Number(capacity_min_dayuse);
    const numericMaxDayuse = Number(capacity_max_dayuse);

    const numericDayUse = Number(day_use);
    const numericIsPet = Number(is_pet);

    // =================================================
    // 2. 객실 그룹 검증
    // =================================================
    if (
      Number.isNaN(numericRoomGroupId) ||
      !Number.isInteger(numericRoomGroupId) ||
      numericRoomGroupId <= 0
    ) {
      return res.status(400).json({
        ok: false,
        message: "room_group_id 값이 올바르지 않습니다.",
      });
    }

    // =================================================
    // 3. 숙박 인원 검증
    // =================================================
    if (
      Number.isNaN(numericMin) ||
      Number.isNaN(numericMax) ||
      numericMin < 0 ||
      numericMax < 0
    ) {
      return res.status(400).json({
        ok: false,
        message: "숙박 인원 값이 올바르지 않습니다.",
      });
    }

    if (numericMin > numericMax) {
      return res.status(400).json({
        ok: false,
        message: "숙박 최소 인원은 숙박 최대 인원보다 클 수 없습니다.",
      });
    }

    // =================================================
    // 4. 데이유즈 인원 검증
    // =================================================
    if (
      Number.isNaN(numericMinDayuse) ||
      Number.isNaN(numericMaxDayuse) ||
      numericMinDayuse < 0 ||
      numericMaxDayuse < 0
    ) {
      return res.status(400).json({
        ok: false,
        message: "데이유즈 인원 값이 올바르지 않습니다.",
      });
    }

    if (numericMinDayuse > numericMaxDayuse) {
      return res.status(400).json({
        ok: false,
        message: "데이유즈 최소 인원은 데이유즈 최대 인원보다 클 수 없습니다.",
      });
    }

    // =================================================
    // 5. 예약 타입 검증
    // 0 = 숙박만
    // 1 = 데이유즈 + 숙박
    // 2 = 데이유즈만
    // =================================================
    if (![0, 1, 2].includes(numericDayUse)) {
      return res.status(400).json({
        ok: false,
        message: "day_use는 0, 1, 2 중 하나여야 합니다.",
      });
    }

    // =================================================
    // 6. 반려동물 수용 여부 검증
    // 0 = 불가능
    // 1 = 가능
    // =================================================
    if (![0, 1].includes(numericIsPet)) {
      return res.status(400).json({
        ok: false,
        message: "is_pet은 0 또는 1이어야 합니다.",
      });
    }

    // =================================================
    // 7. 실제 DB 저장값 계산
    // =================================================
    let finalDayUse = 0;
    let lodgement = 0;

    if (numericDayUse === 0) {
      finalDayUse = 0;
      lodgement = 1;
    } else if (numericDayUse === 1) {
      finalDayUse = 1;
      lodgement = 1;
    } else {
      finalDayUse = 1;
      lodgement = 0;
    }

    const finalDescription = description?.trim() || null;

    // =================================================
    // 8. INSERT
    // =================================================
    const [result] = await pool.query(
      `
      INSERT INTO room
      (
        name,
        description,

        capacity_min,
        capacity_max,

        capacity_min_dayuse,
        capacity_max_dayuse,

        room_group_id,
        available,
        is_active,
        day_use,
        lodgement,
        is_pet,
        reason
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?, NULL)
      `,
      [
        name.trim(),
        finalDescription,

        numericMin,
        numericMax,

        numericMinDayuse,
        numericMaxDayuse,

        numericRoomGroupId,
        finalDayUse,
        lodgement,
        numericIsPet,
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
const messageService = new SolapiMessageService(
  process.env.SOL_API_KEY,
  process.env.SOL_API_SECRET,
);

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
      qty,
      method,
      count,
    } = req.body;

    if (!name || !phone || !startDate || !endDate || !roomInfo) {
      return res.status(400).json({
        ok: false,
        message: "필수값 누락",
      });
    }

    const numericPrice = Number(price);

    if (Number.isNaN(numericPrice) || numericPrice <= 0) {
      return res.status(400).json({
        ok: false,
        message: "금액 오류",
      });
    }

    const allowedMethods = ["CARD", "EPAY", "BANK"];

    const paymentMethod = allowedMethods.includes(
      String(method || "").toUpperCase(),
    )
      ? String(method).toUpperCase()
      : "CARD";

    const check_in = startDate;
    const check_out = endDate;

    const nights = Math.ceil(
      (new Date(check_out) - new Date(check_in)) / (1000 * 60 * 60 * 24),
    );

    /*
     * count는 객실별 인원/반려견 정보
     * 예:
     * [
     *   { people: 2, pets: 1 },
     *   { people: 3, pets: 0 }
     * ]
     */
    const countData = Array.isArray(count) ? count : [];

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
        qty,
        method,
        \`count\`,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
      `,
      [
        roomInfo.room_id || roomInfo.room_group_id,
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
        Number(qty) || 1,
        paymentMethod,
        JSON.stringify(countData),
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

const formatDateForSms = (date) => {
  const d = new Date(date);
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");

  return `${yyyy}-${mm}-${dd}`;
};

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

    const mid = "cafe246818";
    const signKey = process.env.INICIS_SIGN_KEY;

    const oid = `ORD-${reservation.id}-${Date.now()}`;
    const timestamp = Date.now().toString();
    const price = reservation.total_amount.toString();
    //const price = "1000";
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
      returnUrl: "https://dreampingback.duckdns.org:4000/api/payment/return",
      closeUrl: "https://dreampingback.duckdns.org:4000/",
    });
  } catch (error) {
    console.error("payment ready error:", error);

    return res.status(500).json({
      ok: false,
      message: "결제 준비 중 오류 발생",
    });
  }
});

app.post("/api/payment/return", async (req, res) => {
  const conn = await pool.getConnection();

  const getAllSchedules = (room) => {
    let naver = [];
    let soogie = [];

    try {
      naver =
        typeof room.check_in_and_out === "string"
          ? JSON.parse(room.check_in_and_out)
          : room.check_in_and_out || [];
    } catch {
      naver = [];
    }

    try {
      soogie =
        typeof room.check_in_and_out_soogie === "string"
          ? JSON.parse(room.check_in_and_out_soogie)
          : room.check_in_and_out_soogie || [];
    } catch {
      soogie = [];
    }

    return [...naver, ...soogie];
  };

  const isOverlap = (list, start, end) => {
    return list.some((s) => {
      return start <= s.check_out && s.check_in <= end;
    });
  };

  try {
    await conn.beginTransaction();

    let { authToken, authUrl, mid } = req.body || {};

    console.log("return body:", req.body);

    if (!authToken || !authUrl) {
      await conn.rollback();
      return res.json({
        ok: false,
        message: "auth 정보 없음",
      });
    }

    const timestamp = new Date().getTime();
    const signKey = process.env.INICIS_SIGN_KEY;
    // mid fallback
    mid = mid || "cafe246818";
    const signature = crypto
      .createHash("sha256")
      .update("authToken=" + authToken + "&timestamp=" + timestamp)
      .digest("hex");
    const verification = crypto
      .createHash("sha256")
      .update(
        "authToken=" +
          authToken +
          "&signKey=" +
          signKey +
          "&timestamp=" +
          timestamp,
      )
      .digest("hex");
    // =========================
    // 1. 이니시스 승인 요청
    // =========================
    const format = "JSON";
    let response;
    try {
      response = await axios.post(
        authUrl,
        {
          authToken: req.body.authToken,
          mid: req.body.mid,
          charset: req.body.charset,
          signature: signature,
          timestamp: timestamp,
          format: format,
          verification: verification,
        },
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          timeout: 10000,
        },
      );
    } catch (err) {
      await conn.rollback();
      console.error("Inicis request error:", err.message);

      return res.json({
        ok: false,
        message: "이니시스 승인 요청 실패",
      });
    }

    const data = response.data;
    console.log("이니시스 승인 결과:", data);

    // =========================
    // 2. 승인 실패
    // =========================
    if (data.resultCode !== "0000") {
      await conn.query(
        `
        UPDATE reservations_info
        SET status='CANCELLED', updated_at=NOW()
        WHERE order_id=?
        `,
        [data.oid],
      );

      await conn.commit();

      return res.json({
        ok: false,
        message: data.resultMsg || "결제 승인 실패",
      });
    }

    // =========================
    // 3. 예약 조회 (락)
    // =========================
    console.log(data);
    const [rows] = await conn.query(
      `
      SELECT *
      FROM reservations_info
      WHERE order_id=?
      FOR UPDATE
      `,
      [data.MOID],
    );

    if (!rows.length) {
      await conn.rollback();

      return res.json({
        ok: false,
        message: "예약 없음",
      });
    }

    const reservation = rows[0];

    // =========================
    // 4. 금액 검증
    // =========================
    // if (Number(reservation.total_amount) !== Number(data.TotPrice)) {
    //   await conn.query(
    //     `
    //     UPDATE reservations_info
    //     SET status='CANCELLED'
    //     WHERE id=?
    //     `,
    //     [reservation.id],
    //   );

    //   await conn.commit();

    //   return res.json({
    //     ok: false,
    //     message: "금액 불일치",
    //   });
    // }

    // =========================
    // 5. 중복 처리 방지
    // =========================
    if (reservation.status === "PAID") {
      await conn.rollback();

      return res.json({
        ok: true,
        message: "이미 처리됨",
      });
    }

    // =========================
    // 6. 객실 조회
    // =========================
    const [rooms] = await conn.query(
      `
      SELECT *
      FROM room
      WHERE room_group_id=?
      ORDER BY id ASC
      `,
      [reservation.room_group_id],
    );

    let assignedRoomId = null;

    for (const room of rooms) {
      const schedules = getAllSchedules(room);

      if (!isOverlap(schedules, reservation.check_in, reservation.check_out)) {
        assignedRoomId = room.id;
        break;
      }
    }

    if (!assignedRoomId) {
      await conn.rollback();

      // return res.json({
      //   ok: false,
      //   message: "배정 가능한 객실 없음",
      // });
      return res.redirect(
        "https://dreamping.co.kr/shopinfo/payment-cancel.html",
      );
    }

    // =========================
    // 7. room 스케줄 업데이트
    // =========================
    await conn.query(
      `
      UPDATE room
      SET
        check_in=?,
        check_out=?,
        check_in_and_out=JSON_ARRAY_APPEND(
          IFNULL(check_in_and_out, JSON_ARRAY()),
          '$',
          JSON_OBJECT(
            'check_in', ?,
            'check_out', ?,
            'source', 'payment'
          )
        )
      WHERE id=?
      `,
      [
        reservation.check_in,
        reservation.check_out,
        reservation.check_in,
        reservation.check_out,
        assignedRoomId,
      ],
    );

    // =========================
    // 8. 예약 확정
    // =========================
    console.log("this:", data);
    await conn.query(
      `
      UPDATE reservations_info
      SET
        status='PAID',
        room_id=?,
        tid=?,
        updated_at=NOW()
      WHERE id=?
      `,
      [assignedRoomId, data.tid, reservation.id],
    );

    const [groupRows] = await conn.query(
      `
  SELECT name
  FROM room_group
  WHERE id=?
  `,
      [reservation.room_group_id],
    );

    const productName = groupRows.length > 0 ? groupRows[0].name : "객실";
    console.log(formatDateForSms(reservation.check_in));
    try {
      await messageService.send({
        to: reservation.buyer_tel,
        from: process.env.SOLAPI_FROM_NUMBER,
        text: `[드림핑] 예약 완료\n${reservation.buyer_name} 님 예약이 완료되었습니다.\n예약번호: ${reservation.id}\n상품: ${productName}\n체크인:${formatDateForSms(reservation.check_in)}\n체크아웃:${formatDateForSms(reservation.check_out)}\n\n감사합니다.`,
      });
    } catch (smsErr) {
      console.error("SMS send failed:", smsErr.message);
    }

    try {
      await messageService.send({
        to: "01068669088",
        from: process.env.SOLAPI_FROM_NUMBER,
        text: `[드림핑] 예약 완료\n${reservation.buyer_name} 님 예약이 완료되었습니다.\n예약번호: ${reservation.id}\n상품: ${productName}\n체크인:${formatDateForSms(reservation.check_in)}\n체크아웃:${formatDateForSms(reservation.check_out)}\n\n감사합니다.`,
      });
    } catch (smsErr) {
      console.error("SMS send failed:", smsErr.message);
    }

    await conn.commit();

    // return res.json({
    //   ok: true,
    //   message: "결제 성공",
    // });

    return res.redirect(
      `https://dreamping.co.kr/shopinfo/payment-success.html?reservationId=${reservation.id}`,
    );
  } catch (error) {
    await conn.rollback();

    console.error("payment return error:", error);

    // return res.json({
    //   ok: false,
    //   message: error.message || "서버 오류",
    // });
    return res.redirect("https://dreamping.co.kr/shopinfo/payment-cancel.html");
  } finally {
    conn.release();
    syncNaverBookingsToRooms();
  }
});

app.post("/api/payment/innopay/approve", async (req, res) => {
  const conn = await pool.getConnection();

  const getAllSchedules = (room) => {
    let naver = [];
    let soogie = [];

    try {
      naver =
        typeof room.check_in_and_out === "string"
          ? JSON.parse(room.check_in_and_out)
          : room.check_in_and_out || [];
    } catch {
      naver = [];
    }

    try {
      soogie =
        typeof room.check_in_and_out_soogie === "string"
          ? JSON.parse(room.check_in_and_out_soogie)
          : room.check_in_and_out_soogie || [];
    } catch {
      soogie = [];
    }

    return [...naver, ...soogie];
  };

  const isOverlap = (list, start, end) => {
    return list.some((s) => start <= s.check_out && s.check_in <= end);
  };

  try {
    await conn.beginTransaction();

    const {
      paymentToken,
      tid,
      mid,
      amt,
      taxFreeAmt = "0",
      moid,
    } = req.body || {};

    console.log("innopay approve body:", req.body);

    if (!paymentToken || !tid || !mid || !amt || !moid) {
      await conn.rollback();
      return res.json({
        ok: false,
        message: "이노페이 승인 정보 부족",
      });
    }

    let response;

    try {
      response = await axios.post(
        "https://api.innopay.co.kr/v1/transactions/pay",
        {
          tid,
          mid,
          moid,
          amt,
          taxFreeAmt,
        },
        {
          headers: {
            "Payment-Token": paymentToken,
            "Merchant-Key": process.env.INNOPAY_MERCHANT_KEY,
            "Content-Type": "application/json; charset=utf-8",
          },
          timeout: 10000,
        },
      );
    } catch (err) {
      await conn.rollback();

      console.error(
        "Innopay approve request error:",
        err.response?.data || err.message,
      );

      return res.json({
        ok: false,
        message: "이노페이 승인 요청 실패",
        error: err.response?.data || err.message,
      });
    }

    const data = response.data;
    console.log("이노페이 승인 결과:", data);

    if (!data.success) {
      await conn.query(
        `
        UPDATE reservations_info
        SET status='CANCELLED', updated_at=NOW()
        WHERE order_id=?
        `,
        [moid],
      );

      await conn.commit();

      return res.json({
        ok: false,
        message: data.message || data.resultMsg || "결제 승인 실패",
        data,
      });
    }

    const approved = data.data || {};

    const approvedTid = approved.tid || tid;
    const approvedMoid = approved.moid || moid;
    const approvedAmt = approved.amt ?? amt;

    const [rows] = await conn.query(
      `
      SELECT *
      FROM reservations_info
      WHERE order_id=?
      FOR UPDATE
      `,
      [approvedMoid],
    );

    if (!rows.length) {
      await conn.rollback();

      return res.json({
        ok: false,
        message: "예약 없음",
      });
    }

    const reservation = rows[0];

    if (Number(reservation.total_amount) !== Number(approvedAmt)) {
      await conn.query(
        `
        UPDATE reservations_info
        SET status='CANCELLED', updated_at=NOW()
        WHERE id=?
        `,
        [reservation.id],
      );

      await conn.commit();

      return res.json({
        ok: false,
        message: "금액 불일치",
      });
    }

    if (reservation.status === "PAID") {
      await conn.rollback();

      return res.json({
        ok: true,
        message: "이미 처리됨",
        reservationId: reservation.id,
        tid: reservation.tid || approvedTid,
      });
    }

    const [rooms] = await conn.query(
      `
      SELECT *
      FROM room
      WHERE room_group_id=?
      ORDER BY id ASC
      `,
      [reservation.room_group_id],
    );

    const [extraRooms] = await conn.query(
      `
  SELECT *
  FROM extra_room
  WHERE room_group_id=?
    AND start_date <= ?
    AND end_date >= ?
  ORDER BY id ASC
  `,
      [reservation.room_group_id, reservation.check_in, reservation.check_out],
    );

    let assignedRoomId = null;
    let assignedRoomType = null;

    for (const room of rooms) {
      const schedules = getAllSchedules(room);

      if (!isOverlap(schedules, reservation.check_in, reservation.check_out)) {
        assignedRoomId = room.id;
        assignedRoomType = "normal";
        break;
      }
    }
    if (!assignedRoomId) {
      for (const room of extraRooms) {
        const schedules = getAllSchedules(room);

        if (
          !isOverlap(schedules, reservation.check_in, reservation.check_out)
        ) {
          assignedRoomId = room.extra_id;
          assignedRoomType = "extra";
          break;
        }
      }
    }

    if (!assignedRoomId) {
      await conn.rollback();

      return res.json({
        ok: false,
        message: "배정 가능한 객실 없음",
      });
    }

    if (assignedRoomType === "extra") {
      await conn.query(
        `
    UPDATE extra_room
    SET
      check_in=?,
      check_out=?,
      check_in_and_out=JSON_ARRAY_APPEND(
        IFNULL(check_in_and_out, JSON_ARRAY()),
        '$',
        JSON_OBJECT(
          'check_in', ?,
          'check_out', ?,
          'source', 'payment'
        )
      )
    WHERE extra_id=?
    `,
        [
          reservation.check_in,
          reservation.check_out,
          reservation.check_in,
          reservation.check_out,
          assignedRoomId,
        ],
      );
    } else {
      await conn.query(
        `
    UPDATE room
    SET
      check_in=?,
      check_out=?,
      check_in_and_out=JSON_ARRAY_APPEND(
        IFNULL(check_in_and_out, JSON_ARRAY()),
        '$',
        JSON_OBJECT(
          'check_in', ?,
          'check_out', ?,
          'source', 'payment'
        )
      )
    WHERE id=?
    `,
        [
          reservation.check_in,
          reservation.check_out,
          reservation.check_in,
          reservation.check_out,
          assignedRoomId,
        ],
      );
    }

    await conn.query(
      `
      UPDATE reservations_info
      SET
        status='PAID',
        is_innopay=1,
        room_id=?,
        tid=?,
        updated_at=NOW()
      WHERE id=?
      `,
      [assignedRoomId, approvedTid, reservation.id],
    );

    const [groupRows] = await conn.query(
      `
      SELECT name
      FROM room_group
      WHERE id=?
      `,
      [reservation.room_group_id],
    );

    const productName = groupRows.length > 0 ? groupRows[0].name : "객실";

    const [smsRows] = await conn.query(
      `
  SELECT sms_text
  FROM sms_texts
  WHERE sms_type = ?
  LIMIT 1
  `,
      ["reservation_confirm"],
    );

    let smsText = smsRows.length
      ? smsRows[0].sms_text
      : `[드림핑] 예약 완료
${reservation.buyer_name} 님 예약이 완료되었습니다.
예약번호: ${reservation.id}
상품: ${productName}
체크인:${formatDateForSms(reservation.check_in)}
체크아웃:${formatDateForSms(reservation.check_out)}

감사합니다.`;

    smsText = smsText
      .replaceAll("${name}", reservation.buyer_name || "")
      .replaceAll("${reservation_id}", String(reservation.id || ""))
      .replaceAll("${product_name}", productName || "")
      .replaceAll("${check_in}", formatDateForSms(reservation.check_in))
      .replaceAll("${check_out}", formatDateForSms(reservation.check_out));

    try {
      await messageService.send({
        to: reservation.buyer_tel,
        from: process.env.SOLAPI_FROM_NUMBER,
        text: smsText,
      });
    } catch (smsErr) {
      console.error("SMS send failed:", smsErr.message);
    }

    try {
      await messageService.send({
        to: "01068669088",
        from: process.env.SOLAPI_FROM_NUMBER,
        text: smsText,
      });
    } catch (smsErr) {
      console.error("SMS admin send failed:", smsErr.message);
    }

    await conn.commit();

    return res.json({
      ok: true,
      message: "결제 성공",
      reservationId: reservation.id,
      tid: approvedTid,
      receiptUrl: approved.receiptUrl,
      data,
    });
  } catch (error) {
    await conn.rollback();

    console.error("innopay approve error:", error);

    return res.json({
      ok: false,
      message: error.message || "서버 오류",
    });
  } finally {
    conn.release();
    syncNaverBookingsToRooms();
  }
});

// ======================================================
// 모바일 이니시스 결제 시작
// ======================================================
app.get("/api/payment/mobile/start/:reservationId", async (req, res) => {
  try {
    const reservationId = req.params.reservationId;

    if (!reservationId) {
      return res.status(400).send("reservationId 없음");
    }

    // =========================
    // 예약 조회
    // =========================
    const [rows] = await pool.query(
      `
        SELECT *
        FROM reservations_info
        WHERE id = ?
        `,
      [reservationId],
    );

    if (!rows.length) {
      return res.status(404).send("예약 없음");
    }

    const [room_group] = await pool.query(
      `
        SELECT *
        FROM room_group
        WHERE id = ?
        `,
      [rows[0].room_group_id],
    );

    const room_group_name = room_group[0].name;

    const reservation = rows[0];

    if (reservation.status !== "PENDING") {
      return res.send("이미 처리된 예약");
    }

    // =========================
    // 모바일용 주문번호
    // =========================
    const mid = "cafe246818";
    const oid = `${mid}_${Date.now()}`;

    // =========================
    // DB 저장
    // =========================
    await pool.query(
      `
        UPDATE reservations_info
        SET
          order_id = ?,
          updated_at = NOW()
        WHERE id = ?
        `,
      [oid, reservation.id],
    );

    // =========================
    // 이니시스 설정
    // =========================

    const signKey = process.env.INICIS_SIGN_KEY;

    const price = String(Number(reservation.total_amount));
    //const price = "1000";
    const timestamp = Date.now();

    // =========================
    // 모바일 SHA512
    // =========================
    const hashString = price + oid + timestamp + signKey;

    const P_CHKFAKE = crypto
      .createHash("sha512")
      .update(hashString, "utf8")
      .digest("base64");

    // =========================
    // NEXT_URL
    // =========================
    const nextUrl =
      "https://dreampingback.duckdns.org:4000/api/payment/mobile/return";
    const buyerName = reservation.buyer_name;
    const buyerTel = reservation.buyer_tel;
    const buyerEmail = reservation.buyer_email;

    // =========================
    // 모바일 자동 submit 페이지
    // =========================
    return res.send(`
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta
name="viewport"
content="width=device-width, initial-scale=1.0"
/>
<title>모바일 결제</title>
</head>

<body>

<form
name="mobileweb"
method="post"
accept-charset="euc-kr"
action="https://mobile.inicis.com/smart/payment/"
>

<input
type="hidden"
name="P_INI_PAYMENT"
value="CARD"
/>

<input
type="hidden"
name="P_MID"
value="${mid}"
/>

<input
type="hidden"
name="P_OID"
value="${oid}"
/>

<input
type="hidden"
name="P_AMT"
value="${price}"
/>

<input
type="hidden"
name="P_GOODS"
value="${room_group_name}"
/>

<input
type="hidden"
name="P_UNAME"
value="${buyerName}"
/>

<input
type="hidden"
name="P_MOBILE"
value="${buyerTel}"
/>

<input
type="hidden"
name="P_EMAIL"
value="${buyerEmail}"
/>

<input
type="hidden"
name="P_NEXT_URL"
value="${nextUrl}"
/>

<input
type="hidden"
name="P_CHARSET"
value="utf8"
/>

<input
type="hidden"
name="P_TIMESTAMP"
value="${timestamp}"
/>

<input
type="hidden"
name="P_CHKFAKE"
value="${P_CHKFAKE}"
/>

<input
type="hidden"
name="P_NOTI"
value="${reservation.id}"
/>



</form>

<script>

document.mobileweb.submit();

</script>

</body>
</html>
      `);
    console.log("이거 확인", P_CHKFAKE);
  } catch (error) {
    console.error("mobile start error:", error);

    return res.status(500).send("모바일 결제 시작 실패");
  }
});

// ======================================================
// 모바일 이니시스 RETURN
// ======================================================

app.post("/api/payment/mobile/return", async (req, res) => {
  console.log("return run");
  const conn = await pool.getConnection();

  const getAllSchedules = (room) => {
    let naver = [];
    let soogie = [];

    try {
      naver =
        typeof room.check_in_and_out === "string"
          ? JSON.parse(room.check_in_and_out)
          : room.check_in_and_out || [];
    } catch {
      naver = [];
    }

    try {
      soogie =
        typeof room.check_in_and_out_soogie === "string"
          ? JSON.parse(room.check_in_and_out_soogie)
          : room.check_in_and_out_soogie || [];
    } catch {
      soogie = [];
    }

    return [...naver, ...soogie];
  };

  const isOverlap = (list, start, end) => {
    return list.some((s) => {
      return start <= s.check_out && s.check_in <= end;
    });
  };

  try {
    await conn.beginTransaction();

    console.log("mobile return body:", req.body);

    // =========================
    // 1. 인증 실패
    // =========================
    if (req.body.P_STATUS !== "00") {
      await conn.rollback();
      console.log("auth_fail");
      return res.redirect(
        "https://thedreamping2026.cafe24.com/shopinfo/payment-cancel.html",
      );
    }
    console.log("auth_success");
    // =========================
    // 2. 필수값
    // =========================
    const P_TID = req.body.P_TID;

    const P_AMT = req.body.P_AMT;

    const P_NOTI = req.body.P_NOTI;
    const P_UNAME = req.body.P_UNAME;
    console.log("uname:", P_UNAME);

    const idc_name = "ks";

    const P_REQ_URL = req.body.P_REQ_URL;

    if (!P_TID || !P_AMT || !P_NOTI || !P_REQ_URL) {
      await conn.rollback();
      console.log("auth_fail2");
      return res.redirect(
        "https://thedreamping2026.cafe24.com/shopinfo/payment-cancel.html",
      );
    }

    // =========================
    // 3. 승인 URL 검증
    // =========================
    let authUrl = "";

    switch (idc_name) {
      case "fc":
        authUrl = "https://fcmobile.inicis.com/smart/payReq.ini";
        break;

      case "ks":
        authUrl = "https://ksmobile.inicis.com/smart/payReq.ini";
        break;

      case "stg":
        authUrl = "https://stgmobile.inicis.com/smart/payReq.ini";
        break;

      default:
        await conn.rollback();

        return res.redirect(
          "https://thedreamping2026.cafe24.com/shopinfo/payment-cancel.html",
        );
    }

    // 샘플과 동일한 검증
    // if (P_REQ_URL !== authUrl) {
    //   console.log("P_REQ_URL mismatch:", P_REQ_URL, authUrl);

    //   await conn.rollback();

    //   return res.redirect(
    //     "https://thedreamping2026.cafe24.com/shopinfo/payment-cancel.html",
    //   );
    // }

    // =========================
    // 4. 승인 요청
    // =========================
    const params = new URLSearchParams();

    params.append("P_MID", process.env.INICIS_MID);

    params.append("P_TID", P_TID);
    console.log("before_auto");
    const authResponse = await axios.post(P_REQ_URL, params.toString(), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      timeout: 10000,
    });

    // =========================
    // 5. 응답 파싱
    // =========================
    const result = {};

    String(authResponse.data)
      .split("&")
      .forEach((item) => {
        const idx = item.indexOf("=");

        if (idx > -1) {
          const key = item.substring(0, idx);

          const value = decodeURIComponent(item.substring(idx + 1));

          result[key] = value;
        }
      });

    console.log("mobile auth result:", result);

    // =========================
    // 6. 승인 실패
    // =========================
    if (result.P_STATUS !== "00") {
      await conn.query(
        `
          UPDATE reservations_info
          SET
            status='CANCELLED',
            updated_at=NOW()
          WHERE order_id=?
          `,
        [result.P_OID],
      );

      await conn.commit();

      return res.redirect(
        "https://thedreamping2026.cafe24.com/shopinfo/payment-cancel.html",
      );
    }

    // =========================
    // 7. 예약 조회
    // =========================

    const [rows] = await conn.query(
      `
          SELECT *
          FROM reservations_info
          WHERE order_id=?
          FOR UPDATE
          `,
      [result.P_OID],
    );

    if (!rows.length) {
      await conn.rollback();

      return res.send("예약 없음");
    }

    const reservation = rows[0];

    // =========================
    // 8. 중복 방지
    // =========================
    if (reservation.status === "PAID") {
      await conn.rollback();

      return res.redirect(
        "https://thedreamping2026.cafe24.com/shopinfo/payment-success.html",
      );
    }

    // =========================
    // 9. 금액 검증
    // =========================

    const IS_MOBILE_TEST = false;
    if (IS_MOBILE_TEST) {
      if (Number(result.P_AMT) !== 1000) {
        console.log(1000_01);
        return res.redirect(
          "https://thedreamping2026.cafe24.com/shopinfo/payment-cancel.html",
        );
      }
    } else {
      if (Number(reservation.total_amount) !== Number(result.P_AMT)) {
        await conn.query(
          `
            UPDATE reservations_info
            SET
              status='CANCELLED',
              updated_at=NOW()
            WHERE id=?
            `,
          [reservation.id],
        );

        await conn.commit();
        console.log(1000_02);
        return res.redirect(
          "https://thedreamping2026.cafe24.com/shopinfo/payment-cancel.html",
        );
      }
    }

    // =========================
    // 10. 객실 조회
    // =========================
    const [rooms] = await conn.query(
      `
          SELECT *
          FROM room
          WHERE room_group_id=?
          ORDER BY id ASC
          `,
      [reservation.room_group_id],
    );

    let assignedRoomId = null;

    for (const room of rooms) {
      const schedules = getAllSchedules(room);

      if (!isOverlap(schedules, reservation.check_in, reservation.check_out)) {
        assignedRoomId = room.id;

        break;
      }
    }

    // =========================
    // 11. 객실 없음
    // =========================
    if (!assignedRoomId) {
      // 망취소 권장
      try {
        const cancelUrl = authUrl.replace(
          "/smart/payReq.ini",
          "/smart/payNetCancel.ini",
        );

        const cancelParams = new URLSearchParams();

        cancelParams.append("P_TID", P_TID);

        cancelParams.append("P_MID", P_TID.substring(10, 20));

        cancelParams.append("P_AMT", P_AMT);

        cancelParams.append("P_OID", P_NOTI);

        await axios.post(cancelUrl, cancelParams.toString(), {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
        });

        console.log("망취소 완료");
      } catch (cancelError) {
        console.error("망취소 실패:", cancelError);
      }

      await conn.rollback();

      return res.send("배정 가능한 객실 없음");
    }

    // =========================
    // 12. room 업데이트
    // =========================
    await conn.query(
      `
        UPDATE room
        SET
          check_in=?,
          check_out=?,
          check_in_and_out=JSON_ARRAY_APPEND(
            IFNULL(
              check_in_and_out,
              JSON_ARRAY()
            ),
            '$',
            JSON_OBJECT(
              'check_in', ?,
              'check_out', ?,
              'source', 'payment'
            )
          )
        WHERE id=?
        `,
      [
        reservation.check_in,
        reservation.check_out,
        reservation.check_in,
        reservation.check_out,
        assignedRoomId,
      ],
    );

    // =========================
    // 13. 예약 완료
    // =========================
    await conn.query(
      `
        UPDATE reservations_info
        SET
          status='PAID',
          room_id=?,
          tid=?,
          updated_at=NOW()
        WHERE id=?
        `,
      [assignedRoomId, result.P_TID, reservation.id],
    );

    const [groupRows] = await conn.query(
      `SELECT name FROM room_group WHERE id=?`,
      [reservation.room_group_id],
    );

    const productName = groupRows?.[0]?.name || "객실";
    const buyerName = reservation.buyer_name || "고객";

    const text = `[드림핑] 예약 완료\n${buyerName} 님 예약이 완료되었습니다.\n예약번호: ${reservation.id}\n상품: ${productName}\n체크인:${formatDateForSms(reservation.check_in)}\n체크아웃:${formatDateForSms(reservation.check_out)}\n\n감사합니다.`;

    try {
      if (reservation.buyer_tel) {
        await messageService.send({
          to: reservation.buyer_tel,
          from: process.env.SOLAPI_FROM_NUMBER,
          text: text,
        });
      }
    } catch (smsErr) {
      console.error("SMS send failed:", smsErr.message);
    }

    try {
      if (reservation.buyer_tel) {
        await messageService.send({
          to: "01068669088",
          from: process.env.SOLAPI_FROM_NUMBER,
          text: text,
        });
      }
    } catch (smsErr) {
      console.error("SMS send failed:", smsErr.message);
    }

    await conn.commit();

    // =========================
    // 14. 성공 이동
    // =========================
    return res.redirect(
      `https://thedreamping2026.cafe24.com/shopinfo/payment-success.html?reservationId=${reservation.id}`,
    );
  } catch (error) {
    await conn.rollback();

    console.error("mobile return error:", error);

    return res.redirect(
      "https://thedreamping2026.cafe24.com/shopinfo/payment-cancel.html",
    );
  } finally {
    conn.release();
    syncNaverBookingsToRooms();
  }
});
function getTimestamp() {
  const d = new Date();

  const pad = (n) => String(n).padStart(2, "0");

  return (
    d.getFullYear() +
    pad(d.getMonth() + 1) +
    pad(d.getDate()) +
    pad(d.getHours()) +
    pad(d.getMinutes()) +
    pad(d.getSeconds())
  );
}
function pad(number, length) {
  var str = "" + number;
  while (str.length < length) {
    str = "0" + str;
  }
  return str;
}

Date.prototype.YYYYMMDDHHMMSS = function () {
  var yyyy = this.getFullYear().toString();
  var MM = pad(this.getMonth() + 1, 2);
  var dd = pad(this.getDate(), 2);
  var hh = pad(this.getHours(), 2);
  var mm = pad(this.getMinutes(), 2);
  var ss = pad(this.getSeconds(), 2);

  return yyyy + MM + dd + hh + mm + ss;
};

app.post("/api/reservation/refund", async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const { reservationId } = req.body;

    const [rows] = await conn.query(
      `
      SELECT *
      FROM reservations_info
      WHERE id = ?
      `,
      [reservationId],
    );

    if (!rows.length) {
      return res.json({
        ok: false,
        message: "예약 없음",
      });
    }

    const reservation = rows[0];

    if (reservation.status === "CANCELLED") {
      return res.json({
        ok: false,
        message: "이미 환불된 예약",
      });
    }

    if (!reservation.tid) {
      return res.json({
        ok: false,
        message: "TID 없음",
      });
    }

    // -------------------
    // 환불 비율 계산
    // -------------------

    const [refundRows] = await conn.query(
      `
      SELECT *
      FROM refund_info
      ORDER BY day_before DESC
      `,
    );

    const today = new Date();
    const checkIn = new Date(reservation.check_in);

    today.setHours(0, 0, 0, 0);
    checkIn.setHours(0, 0, 0, 0);

    const dayBefore = Math.floor((checkIn - today) / (1000 * 60 * 60 * 24));

    let refundPercent = 0;

    for (const row of refundRows) {
      if (dayBefore >= row.day_before) {
        refundPercent = row.per;
        break;
      }
    }

    // const totalAmount = Number(reservation.total_amount);

    // const refundAmount = Math.floor((totalAmount * refundPercent) / 100);
    const totalAmount = 1000;

    const refundAmount = Math.floor((totalAmount * refundPercent) / 100);

    const confirmPrice = totalAmount - refundAmount;

    console.log({
      dayBefore,
      refundPercent,
      refundAmount,
      confirmPrice,
    });

    const key = process.env.INICIS_API_KEY;
    const mid = process.env.INICIS_MID;

    const timestamp = new Date().YYYYMMDDHHMMSS();

    let type;
    let data;

    // -------------------
    // 100% 환불
    // -------------------

    if (refundPercent === 100) {
      type = "refund";

      data = {
        tid: reservation.tid,
        msg: "고객 환불",
      };
    }

    // -------------------
    // 부분 환불
    // -------------------
    else {
      type = "partialRefund";

      data = {
        tid: reservation.tid,
        msg: "고객 부분환불",
        price: String(refundAmount),
        confirmPrice: String(confirmPrice),
      };
    }

    let plainTxt = key + mid + type + timestamp + JSON.stringify(data);

    plainTxt = plainTxt.replace(/\\/g, "");

    const hashData = crypto.createHash("sha512").update(plainTxt).digest("hex");

    const apiUrl =
      type === "refund"
        ? "https://iniapi.inicis.com/v2/pg/refund"
        : "https://iniapi.inicis.com/v2/pg/partialRefund";

    const result = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        mid,
        type,
        timestamp,
        clientIp: req.ip,
        data,
        hashData,
      }),
    });

    const refundResult = await result.json();

    console.log("refundResult", refundResult);

    if (
      refundResult.resultCode !== "00" &&
      refundResult.resultCode !== "0000"
    ) {
      return res.json({
        ok: false,
        message: refundResult.resultMsg || "환불 실패",
      });
    }

    await conn.query(
      `
      UPDATE reservations_info
      SET
        status = 'CANCELLED',
        refund_percent = ?,
        refund_amount = ?,
        updated_at = NOW()
      WHERE id = ?
      `,
      [refundPercent, refundAmount, reservation.id],
    );

    return res.json({
      ok: true,
      refundPercent,
      refundAmount,
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      ok: false,
      message: "서버 오류",
    });
  } finally {
    conn.release();
    syncNaverBookingsToRooms();
  }
});

app.post("/api/reservation/refund-innopay", async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const { reservationId } = req.body;

    const [rows] = await conn.query(
      `
      SELECT *
      FROM reservations_info
      WHERE id = ?
      `,
      [reservationId],
    );

    if (!rows.length) {
      return res.json({
        ok: false,
        message: "예약 없음",
      });
    }

    const reservation = rows[0];

    if (reservation.status === "CANCELLED") {
      return res.json({
        ok: false,
        message: "이미 환불된 예약",
      });
    }

    if (!reservation.is_innopay) {
      return res.json({
        ok: false,
        message: "이노페이 결제건이 아닙니다.",
      });
    }

    if (!reservation.tid) {
      return res.json({
        ok: false,
        message: "TID 없음",
      });
    }

    const [refundRows] = await conn.query(
      `
      SELECT *
      FROM refund_info
      ORDER BY day_before DESC
      `,
    );

    const today = new Date();
    const checkIn = new Date(reservation.check_in);

    today.setHours(0, 0, 0, 0);
    checkIn.setHours(0, 0, 0, 0);

    const dayBefore = Math.floor((checkIn - today) / (1000 * 60 * 60 * 24));

    let refundPercent = 0;

    for (const row of refundRows) {
      if (dayBefore >= row.day_before) {
        refundPercent = row.per;
        break;
      }
    }

    const totalAmount = Number(reservation.total_amount);
    const refundAmount = Math.floor((totalAmount * refundPercent) / 100);

    if (!refundAmount || refundAmount <= 0) {
      return res.json({
        ok: false,
        message: "환불 금액이 없습니다.",
      });
    }

    const cancelBody = {
      mid: process.env.INNOPAY_MID,
      tid: reservation.tid,
      svcCd: "01",
      partialCancelCode: refundPercent === 100 ? "0" : "1",
      cancelAmt: String(refundAmount),
      cancelMsg: refundPercent === 100 ? "고객 환불" : "고객 부분환불",
      cancelPwd: process.env.INNOPAY_CANCEL_PWD,
    };

    console.log("innopay cancelBody", cancelBody);

    const result = await fetch("https://api.innopay.co.kr/api/cancelApi", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(cancelBody),
    });

    const refundResult = await result.json();

    console.log("innopay refundResult", refundResult);

    if (refundResult.success === false) {
      return res.json({
        ok: false,
        message: refundResult.message || refundResult.resultMsg || "환불 실패",
        data: refundResult,
      });
    }

    await conn.beginTransaction();

    await conn.query(
      `
      UPDATE reservations_info
      SET
        status = 'CANCELLED',
        refund_percent = ?,
        refund_amount = ?,
        updated_at = NOW()
      WHERE id = ?
      `,
      [refundPercent, refundAmount, reservation.id],
    );

    await conn.query(
      `
      UPDATE room_booking_history
      SET canceled = 1
      WHERE booking_id = ?
         OR booking_id = ?
         OR JSON_UNQUOTE(JSON_EXTRACT(payload, '$.reservation_id')) = ?
      `,
      [
        `SITE_${reservation.id}`,
        String(reservation.id),
        String(reservation.id),
      ],
    );

    const [groupRows] = await conn.query(
      `
      SELECT name
      FROM room_group
      WHERE id = ?
      `,
      [reservation.room_group_id],
    );

    const productName = groupRows.length > 0 ? groupRows[0].name : "객실";

    await conn.commit();

    const [smsRows] = await conn.query(
      `
  SELECT sms_text
  FROM sms_texts
  WHERE sms_type = ?
  LIMIT 1
  `,
      ["refund_confirm"],
    );

    let refundSmsText = smsRows.length
      ? smsRows[0].sms_text
      : `[드림핑] 예약 환불 안내
${reservation.buyer_name} 님 예약 환불이 처리되었습니다.
예약번호: ${reservation.id}
상품: ${productName}
체크인:${formatDateForSms(reservation.check_in)}
체크아웃:${formatDateForSms(reservation.check_out)}
환불비율: ${refundPercent}%
환불금액: ${Number(refundAmount).toLocaleString()}원

감사합니다.`;

    refundSmsText = refundSmsText
      .replaceAll("${name}", reservation.buyer_name || "")
      .replaceAll("${reservation_id}", String(reservation.id || ""))
      .replaceAll("${product_name}", productName || "")
      .replaceAll("${check_in}", formatDateForSms(reservation.check_in))
      .replaceAll("${check_out}", formatDateForSms(reservation.check_out))
      .replaceAll("${refund_percent}", String(refundPercent || 0))
      .replaceAll("${price}", Number(refundAmount).toLocaleString());

    try {
      await messageService.send({
        to: reservation.buyer_tel,
        from: process.env.SOLAPI_FROM_NUMBER,
        text: refundSmsText,
      });
    } catch (smsErr) {
      console.error("Refund SMS send failed:", smsErr.message);
    }

    try {
      await messageService.send({
        to: "01068669088",
        from: process.env.SOLAPI_FROM_NUMBER,
        text: refundSmsText,
      });
    } catch (smsErr) {
      console.error("Refund SMS admin send failed:", smsErr.message);
    }

    return res.json({
      ok: true,
      refundPercent,
      refundAmount,
      data: refundResult,
    });
  } catch (err) {
    try {
      await conn.rollback();
    } catch {}

    console.error(err);

    return res.status(500).json({
      ok: false,
      message: "서버 오류",
    });
  } finally {
    conn.release();
    syncNaverBookingsToRooms();
  }
});

app.get("/api/reservation_info_by_moid/:moid", async (req, res) => {
  try {
    const { moid } = req.params;

    const [rows] = await pool.query(
      `
      SELECT *
      FROM reservations_info
      WHERE order_id = ?
      `,
      [moid],
    );

    if (!rows.length) {
      return res.json({
        ok: false,
        message: "예약정보 없음",
      });
    }

    res.json({
      ok: true,
      data: rows[0],
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      ok: false,
      message: "서버 오류",
    });
  }
});

app.get("/api/reservation_info/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const [rows] = await pool.query(
      `
      SELECT
        id,
        room_id,
        room_group_id,
        check_in,
        check_out,
        nights,
        total_amount,
        status,
        order_id,
        buyer_name,
        buyer_tel,
        buyer_email,
        created_at,
        updated_at,
        memo,
        options,
        tid
      FROM reservations_info
      WHERE id = ?
      LIMIT 1
      `,
      [id],
    );

    if (rows.length === 0) {
      return res.status(404).json({
        ok: false,
        message: "예약 정보를 찾을 수 없습니다.",
      });
    }

    const reservation = rows[0];

    return res.json({
      ok: true,
      data: reservation,
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      ok: false,
      message: "서버 오류",
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

app.post("/api/logs", verifyToken, async (req, res) => {
  try {
    const { admin_name, method, endpoint, status_code } = req.body;

    if (!admin_name || !method || !endpoint) {
      return res.status(400).json({
        ok: false,
        message: "필수값 누락",
      });
    }

    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

    await pool.query(
      `
      INSERT INTO admin_logs
      (admin_name, method, endpoint, status_code, ip)
      VALUES (?, ?, ?, ?, ?)
      `,
      [admin_name, method, endpoint, status_code || null, ip],
    );

    return res.json({ ok: true });
  } catch (error) {
    console.error("log error:", error);
    return res.status(500).json({ ok: false });
  }
});

app.get("/api/logs", verifyToken, async (req, res) => {
  try {
    let { page = 1, limit = 10 } = req.query;

    page = parseInt(page);
    limit = parseInt(limit);

    const offset = (page - 1) * limit;

    // 🔹 전체 개수
    const [countRows] = await pool.query(`
      SELECT COUNT(*) as total
      FROM admin_logs
    `);

    const total = countRows[0].total;

    // 🔹 페이지별 데이터
    const [rows] = await pool.query(
      `
      SELECT *
      FROM admin_logs
      ORDER BY id DESC
      LIMIT ? OFFSET ?
      `,
      [limit, offset],
    );

    return res.json({
      ok: true,
      data: rows,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("log get error:", error);
    return res.status(500).json({ ok: false });
  }
});

app.post("/api/naver-status", async (req, res) => {
  try {
    const { action } = req.body;

    // 🔎 필수값 체크
    if (!action) {
      return res.status(400).json({
        ok: false,
        message: "action 값은 필수입니다.",
      });
    }

    // 🔎 허용 값 체크
    const allowed = ["green", "orange", "red"];
    if (!allowed.includes(action)) {
      return res.status(400).json({
        ok: false,
        message: "action 값은 green, orange, red 중 하나여야 합니다.",
      });
    }

    // 🔥 DB insert
    await pool.query(
      `
      INSERT INTO naver_sync_log (action)
      VALUES (?)
      `,
      [action],
    );

    return res.json({
      ok: true,
      message: "상태 저장 완료",
    });
  } catch (error) {
    console.error("naver-status error:", error);
    return res.status(500).json({
      ok: false,
      message: "상태 저장 중 오류 발생",
    });
  }
});

app.get("/api/naver-status", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT id, action, created_at
      FROM naver_sync_log
      ORDER BY id DESC
      LIMIT 1
    `);

    // 🔎 데이터 없을 경우
    if (rows.length === 0) {
      return res.json({
        ok: true,
        data: null,
        message: "아직 상태 로그 없음",
      });
    }

    return res.json({
      ok: true,
      data: rows[0],
    });
  } catch (error) {
    console.error("naver-status get error:", error);
    return res.status(500).json({
      ok: false,
      message: "상태 조회 중 오류 발생",
    });
  }
});
app.get("/api/reservation_history", async (req, res) => {
  try {
    let {
      page = 1,
      limit = 20,

      guest_name = "",
      guest_phone = "",
      memo = "",

      check_in_from = "",
      check_out_to = "",

      payment_from = "",
      payment_to = "",
    } = req.query;

    page = Number(page) || 1;
    limit = Number(limit) || 20;

    if (limit > 100) {
      limit = 100;
    }

    const offset = (page - 1) * limit;

    const where = [];
    const params = [];

    if (guest_name) {
      where.push(`guest_name LIKE ?`);
      params.push(`%${guest_name}%`);
    }

    if (guest_phone) {
      where.push(`guest_phone LIKE ?`);
      params.push(`%${guest_phone}%`);
    }

    if (memo) {
      where.push(`
        (
          memo LIKE ?
          OR manager_memo LIKE ?
        )
      `);

      params.push(`%${memo}%`, `%${memo}%`);
    }

    if (check_in_from && check_out_to) {
      where.push(`
        DATE(check_in) >= ?
        AND DATE(check_out) <= ?
      `);

      params.push(check_in_from, check_out_to);
    }

    const paymentDateSql = `
      CASE
        WHEN source = 'manual'
          OR source = 'website'
          OR source LIKE 'SITE_%'
          OR booking_id LIKE 'SITE_%'
        THEN created_at

        ELSE DATE_ADD(
          STR_TO_DATE(
            SUBSTRING(
              JSON_UNQUOTE(JSON_EXTRACT(payload, '$.payment_date')),
              1,
              19
            ),
            '%Y-%m-%dT%H:%i:%s'
          ),
          INTERVAL 9 HOUR
        )
      END
    `;

    if (payment_from) {
      where.push(`
        ${paymentDateSql} >= ?
      `);

      params.push(`${payment_from} 00:00:00`);
    }

    if (payment_to) {
      where.push(`
        ${paymentDateSql} < DATE_ADD(?, INTERVAL 1 DAY)
      `);

      params.push(`${payment_to} 00:00:00`);
    }

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const [countRows] = await pool.query(
      `
      SELECT COUNT(*) AS total
      FROM room_booking_history
      ${whereSql}
      `,
      params,
    );

    const total = countRows[0]?.total || 0;

    const [rows] = await pool.query(
      `
      SELECT
        id,
        booking_id,
        check_in,
        check_out,
        room_id,
        room_group_id,
        source,
        guest_name,
        guest_phone,
        qty,
        price,
        product_name,
        memo,
        manager_memo,
        canceled,
        payload,
        created_at
      FROM room_booking_history
      ${whereSql}
      ORDER BY id DESC
      LIMIT ?
      OFFSET ?
      `,
      [...params, limit, offset],
    );

    res.json({
      ok: true,
      page,
      limit,
      total,
      totalPage: Math.ceil(total / limit),
      list: rows,
    });
  } catch (err) {
    console.error("reservation_history 조회 실패:", err);

    res.status(500).json({
      ok: false,
      message: "reservation_history 조회 실패",
    });
  }
});

app.post("/api/reservation_history/:id/manager-memo", async (req, res) => {
  try {
    const { id } = req.params;
    const { manager_memo } = req.body;

    if (!id) {
      return res.status(400).json({
        ok: false,
        message: "예약 히스토리 ID가 필요합니다.",
      });
    }

    if (
      manager_memo !== undefined &&
      manager_memo !== null &&
      typeof manager_memo !== "string"
    ) {
      return res.status(400).json({
        ok: false,
        message: "manager_memo는 문자열이어야 합니다.",
      });
    }

    const [historyRows] = await pool.query(
      `
        SELECT
          id,
          source,
          booking_id
        FROM room_booking_history
        WHERE id = ?
        LIMIT 1
        `,
      [id],
    );

    if (historyRows.length === 0) {
      return res.status(404).json({
        ok: false,
        message: "해당 예약 히스토리를 찾을 수 없습니다.",
      });
    }

    const history = historyRows[0];

    const sourceText = String(history.source || "");
    const bookingIdText = String(history.booking_id || "");

    const isManagerMemoTarget =
      sourceText === "naver" ||
      sourceText === "website" ||
      sourceText.startsWith("SITE_") ||
      bookingIdText.startsWith("SITE_");

    if (!isManagerMemoTarget) {
      return res.status(400).json({
        ok: false,
        message:
          "네이버 또는 홈페이지 예약만 관리자 메모를 작성할 수 있습니다.",
      });
    }

    const memoText = manager_memo ?? "";

    await pool.query(
      `
        UPDATE room_booking_history
        SET manager_memo = ?
        WHERE id = ?
        `,
      [memoText, id],
    );

    res.json({
      ok: true,
      message: "관리자 메모가 저장되었습니다.",
      manager_memo: memoText,
    });
  } catch (err) {
    console.error("관리자 메모 저장 실패:", err);

    res.status(500).json({
      ok: false,
      message: "관리자 메모 저장에 실패했습니다.",
    });
  }
});
// GET /api/reservation_info
app.get("/api/reservation_infos", async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();

    const {
      buyer_name,
      check_in_from,
      check_in_to,
      check_out_from,
      check_out_to,
      page = 1,
      limit = 20,
    } = req.query;

    const pageNum = Math.max(Number(page), 1);
    const limitNum = Math.max(Number(limit), 1);
    const offset = (pageNum - 1) * limitNum;

    let where = [];
    let params = [];

    // 결제내역 노출 조건
    // 1) PENDING 제외
    // 2) CANCELLED/CANCELED는 실제 환불금액이 있는 건만 노출
    where.push(`
  COALESCE(status, '') != 'PENDING'
  AND (
    COALESCE(status, '') NOT IN ('CANCELLED', 'CANCELED')
    OR COALESCE(refund_amount, 0) > 0
  )
`);

    // 이름 검색
    if (buyer_name) {
      where.push(`buyer_name LIKE ?`);
      params.push(`%${buyer_name}%`);
    }

    // 체크인 기간
    if (check_in_from) {
      where.push(`check_in >= ?`);
      params.push(check_in_from);
    }

    if (check_in_to) {
      where.push(`check_in < DATE_ADD(?, INTERVAL 1 DAY)`);
      params.push(check_in_to);
    }

    // 체크아웃 기간
    if (check_out_from) {
      where.push(`check_out >= ?`);
      params.push(check_out_from);
    }

    if (check_out_to) {
      where.push(`check_out < DATE_ADD(?, INTERVAL 1 DAY)`);
      params.push(check_out_to);
    }

    const whereSql = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";

    // 전체 개수
    const [countRows] = await conn.query(
      `
      SELECT COUNT(*) AS total
      FROM reservations_info
      ${whereSql}
      `,
      params,
    );

    const total = countRows[0].total;

    // 목록 조회
    const [rows] = await conn.query(
      `
      SELECT *
      FROM reservations_info
      ${whereSql}
      ORDER BY id DESC
      LIMIT ?
      OFFSET ?
      `,
      [...params, limitNum, offset],
    );

    res.json({
      success: true,
      data: rows,
      pagination: {
        total,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(total / limitNum),
      },
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      success: false,
      message: err.message,
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get("/api/sms-texts", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        id,
        sms_type,
        sms_text,
        created_at
      FROM sms_texts
      ORDER BY id ASC
    `);

    return res.json({
      ok: true,
      data: rows,
    });
  } catch (err) {
    console.error("GET /api/sms-texts error:", err);

    return res.status(500).json({
      ok: false,
      message: "SMS 문구 목록 조회 중 오류가 발생했습니다.",
    });
  }
});

app.post("/api/sms-texts", async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const { reservation_confirm, refund_confirm } = req.body;

    await conn.beginTransaction();

    await conn.query(
      `
      UPDATE sms_texts
      SET sms_text = ?
      WHERE sms_type = 'reservation_confirm'
      `,
      [reservation_confirm],
    );

    await conn.query(
      `
      UPDATE sms_texts
      SET sms_text = ?
      WHERE sms_type = 'refund_confirm'
      `,
      [refund_confirm],
    );

    await conn.commit();

    return res.json({
      ok: true,
      message: "SMS 문구가 저장되었습니다.",
    });
  } catch (err) {
    await conn.rollback();
    console.error("POST /api/sms-texts error:", err);

    return res.status(500).json({
      ok: false,
      message: "SMS 문구 저장 중 오류가 발생했습니다.",
    });
  } finally {
    conn.release();
  }
});

// =====================================================
// 임시 객실 생성
// POST /api/extra-room
// =====================================================

app.post("/api/extra-room", async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();

    const {
      name,
      description,
      room_group_id,

      capacity_min,
      capacity_max,

      capacity_min_dayuse,
      capacity_max_dayuse,

      start_date,
      end_date,
      day_use = 1,
      is_pet,
    } = req.body || {};

    // =====================================================
    // 필수값 검증
    // =====================================================
    if (!name || !String(name).trim()) {
      return res.status(400).json({
        success: false,
        message: "객실명을 입력해주세요.",
      });
    }

    if (!room_group_id) {
      return res.status(400).json({
        success: false,
        message: "객실 그룹을 선택해주세요.",
      });
    }

    if (
      capacity_min === undefined ||
      capacity_max === undefined ||
      capacity_min_dayuse === undefined ||
      capacity_max_dayuse === undefined
    ) {
      return res.status(400).json({
        success: false,
        message: "숙박 및 데이유즈 인원 정보를 입력해주세요.",
      });
    }

    if (is_pet === undefined) {
      return res.status(400).json({
        success: false,
        message: "반려동물 수용 여부를 선택해주세요.",
      });
    }

    if (!start_date || !end_date) {
      return res.status(400).json({
        success: false,
        message: "임시 객실 운영 기간을 입력해주세요.",
      });
    }

    if (start_date > end_date) {
      return res.status(400).json({
        success: false,
        message: "시작일은 종료일보다 클 수 없습니다.",
      });
    }

    const numericGroupId = Number(room_group_id);

    const numericCapacityMin = Number(capacity_min);
    const numericCapacityMax = Number(capacity_max);

    const numericCapacityMinDayuse = Number(capacity_min_dayuse);
    const numericCapacityMaxDayuse = Number(capacity_max_dayuse);

    const numericDayUse = Number(day_use);
    const numericIsPet = Number(is_pet);

    // =====================================================
    // 객실 그룹 검증
    // =====================================================
    if (!Number.isInteger(numericGroupId) || numericGroupId <= 0) {
      return res.status(400).json({
        success: false,
        message: "객실 그룹 정보가 올바르지 않습니다.",
      });
    }

    // =====================================================
    // 숙박 인원 검증
    // =====================================================
    if (
      !Number.isFinite(numericCapacityMin) ||
      !Number.isFinite(numericCapacityMax)
    ) {
      return res.status(400).json({
        success: false,
        message: "숙박 인원 수는 숫자로 입력해주세요.",
      });
    }

    if (numericCapacityMin < 0 || numericCapacityMax < 0) {
      return res.status(400).json({
        success: false,
        message: "숙박 인원 수는 0보다 작을 수 없습니다.",
      });
    }

    if (numericCapacityMin > numericCapacityMax) {
      return res.status(400).json({
        success: false,
        message: "숙박 최소 인원은 숙박 최대 인원보다 클 수 없습니다.",
      });
    }

    // =====================================================
    // 데이유즈 인원 검증
    // =====================================================
    if (
      !Number.isFinite(numericCapacityMinDayuse) ||
      !Number.isFinite(numericCapacityMaxDayuse)
    ) {
      return res.status(400).json({
        success: false,
        message: "데이유즈 인원 수는 숫자로 입력해주세요.",
      });
    }

    if (numericCapacityMinDayuse < 0 || numericCapacityMaxDayuse < 0) {
      return res.status(400).json({
        success: false,
        message: "데이유즈 인원 수는 0보다 작을 수 없습니다.",
      });
    }

    if (numericCapacityMinDayuse > numericCapacityMaxDayuse) {
      return res.status(400).json({
        success: false,
        message: "데이유즈 최소 인원은 데이유즈 최대 인원보다 클 수 없습니다.",
      });
    }

    // =====================================================
    // 예약 타입 검증
    // =====================================================
    if (![0, 1, 2].includes(numericDayUse)) {
      return res.status(400).json({
        success: false,
        message: "예약 타입 값이 올바르지 않습니다.",
      });
    }

    // =====================================================
    // 반려동물 수용 여부 검증
    // 0 = 불가능
    // 1 = 가능
    // =====================================================
    if (![0, 1].includes(numericIsPet)) {
      return res.status(400).json({
        success: false,
        message: "is_pet은 0 또는 1이어야 합니다.",
      });
    }

    // =====================================================
    // 그룹 존재 여부 확인
    // =====================================================
    const [groups] = await conn.query(
      `
      SELECT id
      FROM room_group
      WHERE id = ?
      LIMIT 1
      `,
      [numericGroupId],
    );

    if (!groups.length) {
      return res.status(404).json({
        success: false,
        message: "존재하지 않는 객실 그룹입니다.",
      });
    }

    // =====================================================
    // extra_id 생성
    // =====================================================
    const extraId = `EXTRA_${Date.now()}_${crypto
      .randomBytes(4)
      .toString("hex")
      .toUpperCase()}`;

    // =====================================================
    // 저장
    // =====================================================
    const [result] = await conn.query(
      `
      INSERT INTO extra_room (
        extra_id,
        description,
        name,

        capacity_max,
        capacity_min,

        capacity_max_dayuse,
        capacity_min_dayuse,

        room_group_id,
        start_date,
        end_date,
        available,
        is_active,
        day_use,
        lodgement,
        is_pet,
        reason,
        disable_start,
        disable_end,
        is_ota,
        check_in,
        check_out,
        is_soogie,
        check_in_and_out,
        check_in_and_out_soogie,
        soogie,
        naver_crawling_info
      )
      VALUES (
        ?,
        ?,
        ?,

        ?,
        ?,

        ?,
        ?,

        ?,
        ?,
        ?,
        1,
        1,
        ?,
        0,
        ?,
        NULL,
        NULL,
        NULL,
        0,
        NULL,
        NULL,
        0,
        JSON_ARRAY(),
        JSON_ARRAY(),
        NULL,
        JSON_ARRAY()
      )
      `,
      [
        extraId,
        description?.trim() || String(name).trim(),
        String(name).trim(),

        numericCapacityMax,
        numericCapacityMin,

        numericCapacityMaxDayuse,
        numericCapacityMinDayuse,

        numericGroupId,
        start_date,
        end_date,
        numericDayUse,
        numericIsPet,
      ],
    );

    return res.status(201).json({
      success: true,
      message: "임시 객실이 생성되었습니다.",
      data: {
        id: result.insertId,
        extra_id: extraId,
        name: String(name).trim(),
        room_group_id: numericGroupId,

        capacity_min: numericCapacityMin,
        capacity_max: numericCapacityMax,

        capacity_min_dayuse: numericCapacityMinDayuse,
        capacity_max_dayuse: numericCapacityMaxDayuse,

        start_date,
        end_date,
        day_use: numericDayUse,
        is_pet: numericIsPet,
      },
    });
  } catch (error) {
    console.error("POST /api/extra-room 오류:", error);

    if (error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({
        success: false,
        message: "중복된 임시 객실 식별자가 생성되었습니다. 다시 시도해주세요.",
      });
    }

    return res.status(500).json({
      success: false,
      message: "임시 객실 생성 중 오류가 발생했습니다.",
    });
  } finally {
    if (conn) conn.release();
  }
});

export const syncNaverBookingsToRooms = async () => {
  const conn = await pool.getConnection();

  const toKSTDate = (date) =>
    new Intl.DateTimeFormat("sv-SE", {
      timeZone: "Asia/Seoul",
    }).format(new Date(date));

  const normalize = (str) =>
    (str || "").replace(/[^가-힣a-zA-Z0-9]/g, "").toLowerCase();

  const safeParse = (v) => {
    try {
      return typeof v === "string" ? JSON.parse(v) : v || [];
    } catch {
      return [];
    }
  };

  try {
    await conn.beginTransaction();

    console.log("🟡 [SYNC] 시작", new Date().toISOString());

    // =====================================================
    // 1. groups
    // =====================================================
    const [groups] = await conn.query(`
      SELECT id, name
      FROM room_group
      WHERE is_active = 1
    `);

    // =====================================================
    // 2. naver bookings
    // =====================================================
    const [bookings] = await conn.query(`
      SELECT
        booking_id,
        name,
        phone,
        product_name,
        qty,
        price,
        payment_date,
        check_in,
        check_out,
        booking_option,
        request_memo
      FROM naver_bookings
      WHERE cancel_date2 IS NULL
        AND check_out >= DATE_SUB(CURDATE(), INTERVAL 1 DAY)
      ORDER BY check_in ASC
    `);

    // =====================================================
    // 3. website reservations (room_id 무시)
    // =====================================================
    const [siteReservations] = await conn.query(`
      SELECT
        id,
        room_group_id,
        buyer_name,
        buyer_tel,
        total_amount,
        check_in,
        check_out,
        options,
        memo,
        qty
      FROM reservations_info
      WHERE status = 'PAID'
        AND check_out >= DATE_SUB(CURDATE(), INTERVAL 1 DAY)
      ORDER BY check_in ASC
    `);

    // =====================================================
    // 3-1. 기존 OTA 객실 배정 백업
    // reset 전에 반드시 실행해야 한다.
    // =====================================================
    const [previousNormalRooms] = await conn.query(`
  SELECT
    CAST(id AS CHAR) AS room_key,
    naver_crawling_info
  FROM room
`);

    const [previousExtraRooms] = await conn.query(`
  SELECT
    extra_id AS room_key,
    naver_crawling_info
  FROM extra_room
`);

    const makeAssignmentKey = (item) => {
      const isWebsite =
        item.source === "website" ||
        item.reservation_id != null ||
        String(item.booking_id || "").startsWith("SITE_");

      if (isWebsite) {
        const reservationId =
          item.reservation_id ||
          String(item.booking_id || "").replace(/^SITE_/, "");

        return `website|SITE_${reservationId}`;
      }

      return `naver|${String(item.booking_id || "")}`;
    };

    /*
     * 예약 한 건이 qty 2 이상이면 여러 객실에 들어갈 수 있으므로
     * key -> roomKey 배열 형태로 저장한다.
     */
    const previousRoomMap = new Map();

    for (const room of [...previousNormalRooms, ...previousExtraRooms]) {
      const previousItems = safeParse(room.naver_crawling_info);

      for (const item of previousItems) {
        if (!item?.booking_id && !item?.reservation_id) continue;

        const key = makeAssignmentKey(item);
        const previousRoomKeys = previousRoomMap.get(key) || [];

        previousRoomKeys.push(String(room.room_key));
        previousRoomMap.set(key, previousRoomKeys);
      }
    }

    // =====================================================
    // 4. reset
    // =====================================================
    await conn.query(`UPDATE room_group SET check_in_and_out = JSON_ARRAY()`);

    await conn.query(`
      UPDATE room
      SET
        is_active = 1,
        available = 1,
        disable_start = NULL,
        disable_end = NULL,
        check_in = NULL,
        check_out = NULL,
        check_in_and_out = JSON_ARRAY(),
        naver_crawling_info = JSON_ARRAY(),
        is_ota = 0
    `);

    await conn.query(`
  UPDATE extra_room
  SET
    is_active = 1,
    available = 1,
    disable_start = NULL,
    disable_end = NULL,
    check_in = NULL,
    check_out = NULL,
    check_in_and_out = JSON_ARRAY(),
    naver_crawling_info = JSON_ARRAY(),
    is_ota = 0
`);

    // =====================================================
    // 5. group loop
    // =====================================================
    for (const group of groups) {
      const groupId = group.id;

      const normalizeProduct = (str) => {
        const n = normalize(str);

        if (n.includes("오페라")) return "오페라글램핑";

        // 피크닉 R = 레귤러테이블
        if (
          n.includes("피크닉레귤러테이블") ||
          n.includes("피크닉데이레귤러테이블") ||
          n.includes("피크닉레귤러") ||
          n.includes("피크닉데이레귤러")
        ) {
          return n.includes("2부") ? "피크닉r2부" : "피크닉r1부";
        }

        // 피크닉 L = 라지테이블
        if (
          n.includes("피크닉라지테이블") ||
          n.includes("피크닉데이라지테이블") ||
          n.includes("피크닉라지") ||
          n.includes("피크닉데이라지")
        ) {
          return n.includes("2부") ? "피크닉l2부" : "피크닉l1부";
        }

        // 피크닉 G = 자이언트테이블
        if (
          n.includes("피크닉자이언트테이블") ||
          n.includes("피크닉데이자이언트테이블") ||
          n.includes("피크닉자이언트") ||
          n.includes("피크닉데이자이언트")
        ) {
          return n.includes("2부") ? "피크닉g2부" : "피크닉g1부";
        }

        // 이미 피크닉R/G/L 형식으로 들어오는 경우
        if (n.includes("피크닉r"))
          return n.includes("2부") ? "피크닉r2부" : "피크닉r1부";
        if (n.includes("피크닉l"))
          return n.includes("2부") ? "피크닉l2부" : "피크닉l1부";
        if (n.includes("피크닉g"))
          return n.includes("2부") ? "피크닉g2부" : "피크닉g1부";

        return n;
      };

      const normalizeGroup = (str) => {
        const n = normalize(str);

        if (n.includes("피크닉r"))
          return n.includes("2부") ? "피크닉r2부" : "피크닉r1부";
        if (n.includes("피크닉l"))
          return n.includes("2부") ? "피크닉l2부" : "피크닉l1부";
        if (n.includes("피크닉g"))
          return n.includes("2부") ? "피크닉g2부" : "피크닉g1부";

        if (n.includes("오페라")) return "오페라글램핑";

        return n;
      };

      // rooms
      // const [rooms] = await conn.query(
      //   `SELECT id FROM room WHERE room_group_id = ? ORDER BY id ASC`,
      //   [groupId],
      // );

      // const roomSchedules = new Map();
      // for (const r of rooms) roomSchedules.set(r.id, []);

      const [normalRooms] = await conn.query(
        `
  SELECT
    id,
    check_in_and_out_soogie
  FROM room
  WHERE room_group_id = ?
  ORDER BY id ASC
  `,
        [groupId],
      );

      const [extraRooms] = await conn.query(
        `
  SELECT
    id,
    extra_id,
    start_date,
    end_date,
    check_in_and_out_soogie
  FROM extra_room
  WHERE room_group_id = ?
  ORDER BY id ASC
  `,
        [groupId],
      );

      /*
       * normalRooms와 extraRooms를 같은 형식으로 맞춘다.
       *
       * 일반 객실:
       * room_key = 기존 숫자 ID
       *
       * 임시 객실:
       * room_key = EXTRA_... 문자열
       */
      const rooms = [
        ...normalRooms.map((room) => ({
          ...room,
          room_key: String(room.id),
          room_type: "normal",
          start_date: null,
          end_date: null,
        })),

        ...extraRooms.map((room) => ({
          ...room,
          room_key: String(room.extra_id),
          room_type: "extra",
          start_date: toKSTDate(room.start_date),
          end_date: toKSTDate(room.end_date),
        })),
      ];

      const roomSchedules = new Map();

      for (const room of rooms) {
        const manualSchedules = safeParse(room.check_in_and_out_soogie)
          .filter((schedule) => schedule.check_in && schedule.check_out)
          .map((schedule) => ({
            ...schedule,
            source: "manual",
            check_in: toKSTDate(schedule.check_in),
            check_out: toKSTDate(schedule.check_out),
            is_manual_block: true,
          }));

        roomSchedules.set(room.room_key, manualSchedules);
      }

      // =====================================================
      // 5-1. booking + website 합치기 (핵심)
      // =====================================================
      const allPeriods = [];

      for (const b of bookings) {
        const product = normalizeProduct(b.product_name);
        const gname = normalizeGroup(group.name);

        if (
          product === gname ||
          product.includes(gname) ||
          gname.includes(product)
        ) {
          allPeriods.push({
            source: "naver",
            booking_id: b.booking_id,
            product_name: b.product_name,
            payment_date: b.payment_date,
            check_in: toKSTDate(b.check_in),
            check_out: toKSTDate(b.check_out),
            name: b.name,
            phone: b.phone,
            price: b.price,
            qty: b.qty,
            booking_option: b.booking_option,
            request_memo: b.request_memo,
          });
        }
      }
      const groupNameMap = new Map(groups.map((g) => [g.id, g.name]));
      for (const r of siteReservations) {
        if (Number(r.room_group_id) !== Number(groupId)) continue;

        allPeriods.push({
          product_name: groupNameMap.get(r.room_group_id),
          source: "website",
          reservation_id: r.id,
          booking_id: `SITE_${r.id}`,
          check_in: toKSTDate(r.check_in),
          check_out: toKSTDate(r.check_out),
          name: r.buyer_name,
          phone: r.buyer_tel,
          price: r.total_amount,
          qty: r.qty,
          booking_option: safeParse(r.options),
          request_memo: r.memo,
        });
      }

      // =====================================================
      // 5-2. 배정 (바톤터치 유지 핵심)
      // =====================================================

      const makeNaturalKey = (s) => {
        const optionText =
          typeof s.booking_option === "string"
            ? s.booking_option
            : JSON.stringify(s.booking_option || "");

        return [
          s.source,
          s.payment_date || null,
          s.check_in,
          s.check_out,
          s.name,
          s.phone,
          s.product_name,
          s.qty,
          s.price,
          optionText,
          s.request_memo || "",
        ]
          .map((v) => String(v ?? "").trim())
          .join("|");
      };

      const naturalMap = new Map();

      for (const period of allPeriods) {
        const key = makeNaturalKey(period);

        if (naturalMap.has(key)) {
          console.log(
            "⚠️ 중복 예약 배정 제외:",
            period.booking_id,
            "=>",
            naturalMap.get(key).booking_id,
          );
          continue;
        }

        naturalMap.set(key, period);
      }

      const dedupedPeriods = [...naturalMap.values()].sort((a, b) => {
        const aHasPrevious = previousRoomMap.has(makeAssignmentKey(a));
        const bHasPrevious = previousRoomMap.has(makeAssignmentKey(b));

        // 기존 객실 배정이 있는 예약을 먼저 처리
        if (aHasPrevious !== bHasPrevious) {
          return aHasPrevious ? -1 : 1;
        }

        // 같은 조건이면 체크인 날짜순
        return String(a.check_in).localeCompare(String(b.check_in));
      });

      const hasStrictOverlap = (schedule, start, end, isDayUse) => {
        return schedule.some((existing) => {
          const existingIsDayUse = existing.check_in === existing.check_out;

          if (existingIsDayUse && !isDayUse) {
            return existing.check_in >= start && existing.check_in < end;
          }

          if (!existingIsDayUse && isDayUse) {
            return start >= existing.check_in && start < existing.check_out;
          }

          if (existingIsDayUse && isDayUse) {
            return existing.check_in === start;
          }

          return start <= existing.check_out && existing.check_in <= end;
        });
      };

      const hasRelaxedOverlap = (schedule, start, end, isDayUse) => {
        return schedule.some((existing) => {
          const existingIsDayUse = existing.check_in === existing.check_out;

          // 기존 예약이 데이유즈, 새 예약이 숙박
          if (existingIsDayUse && !isDayUse) {
            return existing.check_in >= start && existing.check_in < end;
          }

          // 기존 예약이 숙박, 새 예약이 데이유즈
          if (!existingIsDayUse && isDayUse) {
            return start >= existing.check_in && start < existing.check_out;
          }

          // 데이유즈끼리
          if (existingIsDayUse && isDayUse) {
            return existing.check_in === start;
          }

          // 숙박끼리는 체크아웃일과 다음 체크인을 겹침으로 보지 않는다.
          return start < existing.check_out && existing.check_in < end;
        });
      };

      for (const period of dedupedPeriods) {
        const start = period.check_in;
        const end = period.check_out;
        const qty = Number(period.qty) || 1;
        const isDayUse = start === end;

        const availableRoomsForPeriod = rooms.filter((room) => {
          if (room.room_type === "normal") {
            return true;
          }

          return room.start_date <= start && room.end_date >= end;
        });

        const assignmentKey = makeAssignmentKey(period);
        const previousRoomKeys = previousRoomMap.get(assignmentKey) || [];

        for (let q = 0; q < qty; q++) {
          let assigned = false;

          // =====================================================
          // 0차 배정: 기존에 사용하던 객실 유지
          // =====================================================
          const previousRoomKey = previousRoomKeys[q];

          if (previousRoomKey) {
            const previousRoom = availableRoomsForPeriod.find(
              (room) => String(room.room_key) === String(previousRoomKey),
            );

            if (previousRoom) {
              const schedule = roomSchedules.get(previousRoom.room_key) || [];

              /*
               * 기존 객실 유지 시에는 바톤터치가 허용된 최종 겹침 규칙을
               * 사용한다. 그래야 체크아웃/체크인 연결 때문에 다른 방으로
               * 이동하지 않는다.
               */
              const overlap = hasRelaxedOverlap(schedule, start, end, isDayUse);

              if (!overlap) {
                schedule.push(period);
                roomSchedules.set(previousRoom.room_key, schedule);
                assigned = true;

                console.log(
                  "🟢 기존 객실 유지:",
                  period.booking_id || period.reservation_id,
                  "=>",
                  previousRoom.room_key,
                );
              }
            }
          }

          // =====================================================
          // 1차 배정: 기존의 엄격한 겹침 판단
          // =====================================================
          if (!assigned) {
            for (const room of availableRoomsForPeriod) {
              const schedule = roomSchedules.get(room.room_key) || [];

              if (!hasStrictOverlap(schedule, start, end, isDayUse)) {
                schedule.push(period);
                roomSchedules.set(room.room_key, schedule);
                assigned = true;
                break;
              }
            }
          }

          // =====================================================
          // 2차 배정: 바톤터치 허용
          // =====================================================
          if (!assigned) {
            for (const room of availableRoomsForPeriod) {
              const schedule = roomSchedules.get(room.room_key) || [];

              if (!hasRelaxedOverlap(schedule, start, end, isDayUse)) {
                schedule.push(period);
                roomSchedules.set(room.room_key, schedule);
                assigned = true;
                break;
              }
            }
          }

          if (!assigned) {
            console.warn(
              "[FAIL]",
              period.booking_id || period.reservation_id,
              `qty index: ${q}`,
            );
          }
        }
      }

      // =====================================================
      // 5-3. 일반 객실 + 임시 객실 저장
      // =====================================================
      for (const room of rooms) {
        const roomKey = room.room_key;
        const schedule = roomSchedules.get(roomKey) || [];

        const otaSchedule = schedule.filter((item) => !item.is_manual_block);

        if (!schedule.length) {
          continue;
        }

        schedule.sort((a, b) => a.check_in.localeCompare(b.check_in));

        otaSchedule.sort((a, b) => a.check_in.localeCompare(b.check_in));

        const first = schedule[0];

        const scheduleJson = JSON.stringify(
          otaSchedule.map((item) => ({
            check_in: item.check_in,
            check_out: item.check_out,
            source: item.source,
          })),
        );

        const crawlingInfoJson = JSON.stringify(
          otaSchedule.map((item) => ({
            booking_id: item.booking_id,
            reservation_id: item.reservation_id,
            product_name: item.product_name,
            payment_date: item.payment_date || null,
            name: item.name,
            phone: item.phone,
            price: item.price,
            qty: item.qty,
            booking_option: item.booking_option,
            request_memo: item.request_memo,
            check_in: item.check_in,
            check_out: item.check_out,
          })),
        );

        if (room.room_type === "extra") {
          await conn.query(
            `
      UPDATE extra_room
      SET
        is_active = 0,
        available = 0,
        disable_start = ?,
        disable_end = ?,
        check_in = ?,
        check_out = ?,
        check_in_and_out = ?,
        naver_crawling_info = ?
      WHERE extra_id = ?
      `,
            [
              first.check_in,
              first.check_out,
              first.check_in,
              first.check_out,
              scheduleJson,
              crawlingInfoJson,
              roomKey,
            ],
          );
        } else {
          await conn.query(
            `
      UPDATE room
      SET
        is_active = 0,
        available = 0,
        disable_start = ?,
        disable_end = ?,
        check_in = ?,
        check_out = ?,
        check_in_and_out = ?,
        naver_crawling_info = ?
      WHERE id = ?
      `,
            [
              first.check_in,
              first.check_out,
              first.check_in,
              first.check_out,
              scheduleJson,
              crawlingInfoJson,
              roomKey,
            ],
          );
        }

        // =====================================================
        // history
        // =====================================================
        for (const item of otaSchedule) {
          const bookingId =
            item.source === "website"
              ? `SITE_${item.reservation_id}`
              : String(item.booking_id);

          const payload = {
            booking_id: bookingId,
            reservation_id: item.reservation_id || null,
            product_name: item.product_name,
            payment_date: item.payment_date || null,
            name: item.name,
            phone: item.phone,
            price: item.price,
            qty: item.qty,
            booking_option: item.booking_option,
            request_memo: item.request_memo,
            check_in: item.check_in,
            check_out: item.check_out,
          };

          const [exists] = await conn.query(
            `
      SELECT
        id,
        booking_id,
        canceled
      FROM room_booking_history
      WHERE source = ?
        AND room_id = ?
        AND room_group_id = ?
        AND check_in = ?
        AND check_out = ?
        AND guest_name = ?
        AND guest_phone = ?
        AND qty = ?
        AND price = ?
        AND product_name <=> ?
        AND JSON_UNQUOTE(
          JSON_EXTRACT(payload, '$.payment_date')
        ) = ?
      LIMIT 1
      `,
            [
              item.source,
              String(roomKey),
              groupId,
              item.check_in,
              item.check_out,
              item.name,
              item.phone,
              item.qty,
              item.price,
              item.product_name || null,
              item.payment_date || null,
            ],
          );

          if (exists.length) {
            await conn.query(
              `
        UPDATE room_booking_history
        SET
          payload = ?,
          booking_id = ?,
          room_id = ?,
          room_group_id = ?,
          canceled = 0
        WHERE id = ?
        `,
              [
                JSON.stringify(payload),
                bookingId,
                String(roomKey),
                groupId,
                exists[0].id,
              ],
            );
          } else {
            await conn.query(
              `
        INSERT INTO room_booking_history (
          payload,
          booking_id,
          check_in,
          check_out,
          room_id,
          room_group_id,
          source,
          guest_name,
          guest_phone,
          qty,
          price,
          product_name,
          canceled
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        `,
              [
                JSON.stringify(payload),
                bookingId,
                item.check_in,
                item.check_out,
                String(roomKey),
                groupId,
                item.source,
                item.name,
                item.phone,
                item.qty,
                item.price,
                item.product_name || null,
              ],
            );
          }
        }
      }
    }

    await conn.query(`
  DELETE h1
  FROM room_booking_history h1
  JOIN room_booking_history h2
    ON h1.id > h2.id
   AND h1.source = h2.source
   AND h1.booking_id = h2.booking_id
   AND h1.check_in = h2.check_in
   AND h1.check_out = h2.check_out
   AND h1.guest_name = h2.guest_name
   AND h1.guest_phone = h2.guest_phone
   AND h1.qty = h2.qty
   AND h1.price = h2.price
   AND h1.product_name <=> h2.product_name
`);

    await conn.query(`
  UPDATE room_booking_history
  SET canceled = 0
  WHERE source = 'naver'
`);

    const [canceledBookings] = await conn.query(`
  SELECT
    booking_id,
    name,
    phone,
    product_name,
    qty,
    price,
  payment_date,
    check_in,
    check_out
  FROM naver_bookings
  WHERE cancel_date2 IS NOT NULL
`);

    for (const booking of canceledBookings) {
      // 1) booking_id 우선
      const [byId] = await conn.query(
        `
  UPDATE room_booking_history
  SET canceled = 1
  WHERE source = 'naver'
    AND canceled = 0
    AND booking_id = ?
  `,
        [String(booking.booking_id)],
      );

      if (byId.affectedRows > 0) continue;

      // 2) natural fallback 후보 조회
      const [candidates] = await conn.query(
        `
SELECT id, booking_id
FROM room_booking_history
WHERE source = 'naver'
  AND canceled = 0
  AND check_in = ?
  AND check_out = ?
  AND guest_name = ?
  AND guest_phone = ?
  AND qty = ?
  AND product_name <=> ?
  AND ABS(
    TIMESTAMPDIFF(
      SECOND,
      STR_TO_DATE(
        LEFT(REPLACE(JSON_UNQUOTE(JSON_EXTRACT(payload, '$.payment_date')), 'T', ' '), 19),
        '%Y-%m-%d %H:%i:%s'
      ),
      STR_TO_DATE(
        LEFT(REPLACE(?, 'T', ' '), 19),
        '%Y-%m-%d %H:%i:%s'
      )
    )
  ) <= 2
  `,
        [
          toKSTDate(booking.check_in),
          toKSTDate(booking.check_out),
          booking.name,
          booking.phone,
          booking.qty,
          booking.product_name || null,
          booking.payment_date,
        ],
      );

      // 3) 정확히 하나일 때만 취소
      if (candidates.length === 1) {
        await conn.query(
          `
    UPDATE room_booking_history
    SET canceled = 1
    WHERE id = ?
    `,
          [candidates[0].id],
        );
      } else {
        console.warn("⚠️ [CANCEL FALLBACK SKIP]", {
          booking_id: booking.booking_id,
          candidateCount: candidates.length,
          candidates,
          name: booking.name,
          phone: booking.phone,
          check_in: toKSTDate(booking.check_in),
          check_out: toKSTDate(booking.check_out),
        });
      }
    }

    await conn.commit();
    console.log("🟢 [SYNC 완료]");
  } catch (err) {
    await conn.rollback();
    console.error("🔴 [SYNC ERROR]", err);
  } finally {
    conn.release();
  }
};

syncNaverBookingsToRooms();
// 10분 주기 실행
let isSyncing = false;

setInterval(
  async () => {
    if (isSyncing) return;
    isSyncing = true;

    try {
      await syncNaverBookingsToRooms();
    } finally {
      isSyncing = false;
    }
  },
  1000 * 60 * 5, // 5분
);

// 초기 1회 실행

export const expirePendingReservations = async (conn) => {
  await conn.query(`
   UPDATE reservations_info
    SET status = 'CANCELLED',
        updated_at = NOW()
    WHERE status = 'PENDING'
      AND created_at < NOW() - INTERVAL 30 MINUTE
  `);
};

// 10분 주기 실행
let isSyncing2 = false;

const runExpireJob = async () => {
  if (isSyncing2) return;
  isSyncing2 = true;

  const conn = await pool.getConnection();

  try {
    await expirePendingReservations(conn);
  } catch (err) {
    console.error("expire job error:", err);
  } finally {
    conn.release();
    isSyncing2 = false;
  }
};

// 초기 실행
runExpireJob();

// 10분 주기
setInterval(runExpireJob, 1000 * 60 * 10);

app.get("/api/for_debuging", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM naver_bookings ORDER BY id ASC`,
    );
    const [rows2] = await pool.query(
      `SELECT * FROM room_group ORDER BY id ASC`,
    );
    const [rows3] = await pool.query(`SELECT * FROM room ORDER BY id ASC`);
    return res.json({
      ok: true,
      naver_data: rows,
      our_data: rows2,
      room: rows3,
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

app.use("/uploads", express.static("uploads"));

// 404 핸들러
app.use((req, res, next) => {
  res.status(404).json({ message: "Not Found" });
});

// 에러 핸들러
app.use(errorMiddleware);
//a
export default app;
