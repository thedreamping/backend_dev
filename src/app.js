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
      [numericChanged, id]
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

app.post("/api/main-event-popup", upload.array("file"), async (req, res) => {
  try {
    const files = req.files || [];

    // multer + formData 특성상
    const normalizeToArray = (value) => {
      if (value === undefined || value === null) return [];
      return Array.isArray(value) ? value : [value];
    };

    const file_name = normalizeToArray(req.body.file_name);
    const width = normalizeToArray(req.body.width);
    const height = normalizeToArray(req.body.height);
    const link = normalizeToArray(req.body.link);
    const file_url = normalizeToArray(req.body.file_url);
    const is_use = normalizeToArray(req.body.is_use);
    const file_index = normalizeToArray(req.body.file_index); // 새 파일의 슬라이드 index

    // 필수값 체크
    if (
      !width.length ||
      width.length !== link.length ||
      height.length !== width.length ||
      height.length !== is_use.length
    ) {
      return res.status(400).json({ message: "데이터 형식 오류" });
    }

    // 🔥 기존 데이터 전체 삭제
    await pool.query("DELETE FROM main_popup");

    // 새 파일과 슬라이드를 index로 매칭
    const fileMap = {}; // index: fileUrl
    files.forEach((file, idx) => {
      const index = parseInt(file_index[idx], 10);
      if (!isNaN(index)) {
        fileMap[index] = `/uploads/${file.filename}`;
      }
    });

    for (let i = 0; i < width.length; i++) {
      let finalFileUrl;

      // 새 파일이 있으면 해당 index에서 가져오기
      if (fileMap[i]) {
        finalFileUrl = fileMap[i];
      }
      // 새 파일 없으면 기존 파일 유지
      else if (file_url[i] !== undefined && file_url[i] !== "") {
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
        INSERT INTO main_popup (file_name, width, link, file_url, height, is_use)
        VALUES (?, ?, ?, ?, ?, ?)
        `,
        [
          file_name[i] || "",
          width[i],
          link[i],
          finalFileUrl,
          height[i],
          is_use[i],
        ],
      );
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error("main-popup save error:", err);
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
    const [rows] = await pool.query(`SELECT * FROM main_popup ORDER BY id ASC`);

    return res.json({
      ok: true,
      data: rows,
    });
  } catch (err) {
    console.error("main_popup fetch error:", err);
    return res.status(500).json({
      ok: false,
      message: "메인 룸 배너 조회 중 오류 발생",
    });
  }
});
app.post("/api/room-price", verifyToken, async (req, res) => {
  try {
    const { dates, rooms } = req.body;

    if (!Array.isArray(dates) || !Array.isArray(rooms)) {
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

    const conn = await pool.getConnection();
    await conn.beginTransaction();

    try {
      // 🔥 날짜 기준 전체 삭제
      const placeholders = dates.map(() => "?").join(",");

      await conn.query(
        `DELETE FROM room_price WHERE date IN (${placeholders})`,
        dates
      );

      // 🔥 새로 INSERT
      await conn.query(
        `
        INSERT INTO room_price 
        (room_group_id, date, price, room_group_name)
        VALUES ?
        `,
        [insertValues]
      );

      await conn.commit();

      return res.json({
        ok: true,
        message: "날짜 기준 전체 덮어쓰기 완료",
      });

    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }

  } catch (error) {
    console.error("room_price replace error:", error);
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

    const {
      name,
      is_active,
      reason,
      capacity_max,
      capacity_min,
      day_use,
      disable_start,
      disable_end,
      manual_booking,
      cancel_booking
    } = req.body;

    // =================================================
    // 1️⃣ 필수값 체크
    // =================================================
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

    if (![0, 1, 2].includes(numericDayUse)) {
      return res.status(400).json({
        ok: false,
        message: "day_use는 0, 1, 2 중 하나여야 합니다.",
      });
    }

    // =================================================
    // 2️⃣ 예약 타입 계산
    // 0 = 숙박만
    // 1 = 데이+숙박
    // 2 = 데이만
    // =================================================
    let finalDayUse = 0;
    let lodgement = 0;

    if (numericDayUse === 0) {
      finalDayUse = 0;
      lodgement = 1;
    } else if (numericDayUse === 1) {
      finalDayUse = 1;
      lodgement = 1;
    } else if (numericDayUse === 2) {
      finalDayUse = 1;
      lodgement = 0;
    }

    // =================================================
    // 3️⃣ 비활성화 체크
    // =================================================
    if (Number(is_active) === 0) {
      if (!reason || reason.trim() === "") {
        return res.status(400).json({
          ok: false,
          message: "비활성화 시 사유는 필수입니다.",
        });
      }

      if (!disable_start || !disable_end) {
        return res.status(400).json({
          ok: false,
          message: "비활성 기간은 필수입니다.",
        });
      }

      if (disable_start > disable_end) {
        return res.status(400).json({
          ok: false,
          message: "시작일은 종료일보다 클 수 없습니다.",
        });
      }
    }

    // =================================================
    // 4️⃣ 기존 데이터 조회
    // =================================================
    const [roomRows] = await pool.query(
      `SELECT room_group_id, is_ota, check_in_and_out_soogie
       FROM room
       WHERE id = ?`,
      [id]
    );

    if (roomRows.length === 0) {
      return res.status(404).json({
        ok: false,
        message: "해당 객실을 찾을 수 없습니다.",
      });
    }

    const roomGroupId = roomRows[0].room_group_id;
    const currentIsOta = roomRows[0].is_ota;

    // =================================================
    // 5️⃣ 수기예약 JSON 파싱
    // =================================================
    let finalSoogieSchedule = [];

    try {
      finalSoogieSchedule = roomRows[0].check_in_and_out_soogie
        ? JSON.parse(roomRows[0].check_in_and_out_soogie)
        : [];
    } catch {
      finalSoogieSchedule = [];
    }

    // =================================================
    // 6️⃣ 수기예약 추가
    // =================================================
    if (manual_booking && Number(is_active) === 0) {
      finalSoogieSchedule.push(manual_booking);
    }

    // =================================================
    // 7️⃣ 수기예약 취소
    // =================================================
    if (cancel_booking) {
      finalSoogieSchedule = finalSoogieSchedule.filter((b) => {
        return !(
          b.check_in === cancel_booking.check_in &&
          b.check_out === cancel_booking.check_out
        );
      });
    }

    // =================================================
    // 8️⃣ 상태 계산
    // =================================================
    const finalReason = Number(is_active) === 1 ? null : reason?.trim();
    const finalStart = Number(is_active) === 1 ? null : disable_start;
    const finalEnd = Number(is_active) === 1 ? null : disable_end;

    const finalCheckIn = finalStart;
    const finalCheckOut = finalEnd;

    const finalSoogie = finalSoogieSchedule.length > 0 ? 1 : 0;
    const finalIsActive =
      finalSoogieSchedule.length > 0 ? 0 : Number(is_active);

    const finalIsOta = finalSoogie === 1 ? 0 : currentIsOta;

    // =================================================
    // 9️⃣ 그룹 전체 옵션 업데이트
    // =================================================
    await pool.query(
      `
      UPDATE room
      SET capacity_max = ?,
          capacity_min = ?,
          day_use = ?,
          lodgement = ?
      WHERE room_group_id = ?
      `,
      [numericMax, numericMin, finalDayUse, lodgement, roomGroupId]
    );

    // =================================================
    // 🔟 개별 room 업데이트
    // =================================================
    await pool.query(
      `
      UPDATE room
      SET name = ?,
          is_active = ?,
          reason = ?,
          disable_start = ?,
          disable_end = ?,
          check_in = ?,
          check_out = ?,
          is_soogie = ?,
          is_ota = ?,
          check_in_and_out_soogie = ?
      WHERE id = ?
      `,
      [
        name.trim(),
        finalIsActive,
        finalReason,
        finalStart,
        finalEnd,
        finalCheckIn,
        finalCheckOut,
        finalSoogie,
        finalIsOta,
        JSON.stringify(finalSoogieSchedule),
        id,
      ]
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
    const {
      name,
      is_active,
      reason,
      disable_start,
      disable_end,
    } = req.body;

    // ✅ 필수값 체크
    if (!name || typeof is_active === "undefined") {
      await connection.rollback();
      return res.status(400).json({
        ok: false,
        message: "name, is_active는 필수입니다.",
      });
    }

    // ✅ 비활성화 조건
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

      if (disable_start > disable_end) {
        await connection.rollback();
        return res.status(400).json({
          ok: false,
          message: "시작일은 종료일보다 클 수 없습니다.",
        });
      }
    }

    const finalReason =
      Number(is_active) === 1 ? null : reason.trim();

    const finalStart =
      Number(is_active) === 1 ? null : disable_start;

    const finalEnd =
      Number(is_active) === 1 ? null : disable_end;

    // 1️⃣ 그룹 업데이트
    const [result] = await connection.query(
      `
      UPDATE room_group
      SET 
        name = ?, 
        is_active = ?, 
        reason = ?,
        disable_start = ?,
        disable_end = ?
      WHERE id = ?
      `,
      [
        name,
        Number(is_active),
        finalReason,
        finalStart,
        finalEnd,
        id,
      ]
    );

    if (result.affectedRows === 0) {
      await connection.rollback();
      return res.status(404).json({
        ok: false,
        message: "해당 객실 그룹을 찾을 수 없습니다.",
      });
    }

    // 2️⃣ 하위 room 동기화

    if (Number(is_active) === 0) {
      // 🔥 비활성화
      await connection.query(
        `
        UPDATE room
        SET 
          is_active = 0,
          reason = '상위 그룹 비활성화',
          disable_start = ?,
          disable_end = ?
        WHERE room_group_id = ?
        `,
        [finalStart, finalEnd, id]
      );
    }

    if (Number(is_active) === 1) {
      // 🔥 활성화
      await connection.query(
        `
        UPDATE room
        SET 
          is_active = 1,
          reason = NULL,
          disable_start = NULL,
          disable_end = NULL
        WHERE room_group_id = ?
        `,
        [id]
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

app.put("/api/rooms/bulk-update", verifyToken, async (req, res) => {
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();

    const {
      ids,
      is_active,
      reason,
      disable_start,
      disable_end,
    } = req.body;

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

    const finalReason =
      Number(is_active) === 1 ? null : reason.trim();

    const finalStart =
      Number(is_active) === 1 ? null : disable_start;

    const finalEnd =
      Number(is_active) === 1 ? null : disable_end;

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
      [
        Number(is_active),
        finalReason,
        finalStart,
        finalEnd,
        ...ids,
      ]
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

    // =================================================
    // 1️⃣ 필수값 체크
    // =================================================
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

    if (![0, 1, 2].includes(numericDayUse)) {
      return res.status(400).json({
        ok: false,
        message: "day_use는 0, 1, 2 중 하나여야 합니다.",
      });
    }

    // =================================================
    // 2️⃣ 예약 타입 계산
    // 0 = 숙박만
    // 1 = 데이+숙박
    // 2 = 데이만
    // =================================================
    let finalDayUse = 0;
    let lodgement = 0;

    if (numericDayUse === 0) {
      finalDayUse = 0;
      lodgement = 1;
    } else if (numericDayUse === 1) {
      finalDayUse = 1;
      lodgement = 1;
    } else if (numericDayUse === 2) {
      finalDayUse = 1;
      lodgement = 0;
    }

    const finalDescription =
      description && description.trim() !== ""
        ? description.trim()
        : null;

    // =================================================
    // 3️⃣ INSERT
    // =================================================
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
        finalDayUse,
        lodgement,
      ]
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
      VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, NOW(), NOW())
      `,
      [
        roomInfo.room_group_id,
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

    const mid = "cafe246818";
    const signKey = process.env.INICIS_SIGN_KEY;

    const oid = `ORD-${reservation.id}-${Date.now()}`;
    const timestamp = Date.now().toString();
    // const price = reservation.total_amount.toString();
    const price = "1000";
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
        message: "auth 정보 없음"
      });
    }

      const timestamp = new Date().getTime(); 

    // mid fallback
    mid = mid || "cafe246818";
    const signature  = crypto.createHash("sha256").update("authToken="+authToken+"&timestamp="+timestamp).digest('hex');
    // =========================
    // 1. 이니시스 승인 요청
    // =========================
    const format = "JSON"
    let response;
    try {
      response = await axios.post(
        authUrl,
        {
          authToken:req.body.authToken,
          mid:req.body.mid,
          charset:req.body.charset,
          signature:signature,
          timestamp:timestamp,
          format:format
        },
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded"
          },
          timeout: 10000
        }
      );
    } catch (err) {
      await conn.rollback();
      console.error("Inicis request error:", err.message);

      return res.json({
        ok: false,
        message: "이니시스 승인 요청 실패"
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
        [data.oid]
      );

      await conn.commit();

      return res.json({
        ok: false,
        message: data.resultMsg || "결제 승인 실패"
      });
    }

    // =========================
    // 3. 예약 조회 (락)
    // =========================
    const [rows] = await conn.query(
      `
      SELECT *
      FROM reservations_info
      WHERE order_id=?
      FOR UPDATE
      `,
      [data.oid]
    );

    if (!rows.length) {
      await conn.rollback();

      return res.json({
        ok: false,
        message: "예약 없음"
      });
    }

    const reservation = rows[0];

    // =========================
    // 4. 금액 검증
    // =========================
    if (Number(reservation.total_amount) !== Number(data.totPrice)) {
      await conn.query(
        `
        UPDATE reservations_info
        SET status='CANCELLED'
        WHERE id=?
        `,
        [reservation.id]
      );

      await conn.commit();

      return res.json({
        ok: false,
        message: "금액 불일치"
      });
    }

    // =========================
    // 5. 중복 처리 방지
    // =========================
    if (reservation.status === "PAID") {
      await conn.rollback();

      return res.json({
        ok: true,
        message: "이미 처리됨"
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
      [reservation.room_group_id]
    );

    let assignedRoomId = null;

    for (const room of rooms) {
      const schedules = getAllSchedules(room);

      if (
        !isOverlap(
          schedules,
          reservation.check_in,
          reservation.check_out
        )
      ) {
        assignedRoomId = room.id;
        break;
      }
    }

    if (!assignedRoomId) {
      await conn.rollback();

      return res.json({
        ok: false,
        message: "배정 가능한 객실 없음"
      });
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
        assignedRoomId
      ]
    );

    // =========================
    // 8. 예약 확정
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
      [assignedRoomId, data.tid, reservation.id]
    );

    await conn.commit();

    return res.json({
      ok: true,
      message: "결제 성공"
    });
  } catch (error) {
    await conn.rollback();

    console.error("payment return error:", error);

    return res.json({
      ok: false,
      message: error.message || "서버 오류"
    });
  } finally {
    conn.release();
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

    const ip =
      req.headers["x-forwarded-for"] || req.socket.remoteAddress;



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
      [limit, offset]
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
      [action]
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

export const syncNaverBookingsToRooms = async () => {
  const conn = await pool.getConnection();

  try {
    await conn.beginTransaction();

    console.log("🟡 [SYNC] 시작", new Date().toISOString());
     const toKSTDate = (date) =>
      new Intl.DateTimeFormat("sv-SE", {
        timeZone: "Asia/Seoul",
      }).format(new Date(date));

    const today = toKSTDate(new Date());

    const [manualRooms] = await conn.query(`
      SELECT id, check_in_and_out_soogie
      FROM room
      WHERE check_in_and_out_soogie IS NOT NULL
    `);

    for (const room of manualRooms) {
      let schedules = [];

      try {
        schedules = Array.isArray(room.check_in_and_out_soogie)
          ? room.check_in_and_out_soogie
          : JSON.parse(room.check_in_and_out_soogie || "[]");
      } catch {
        schedules = [];
      }

      const filtered = schedules.filter(
        (s) => s.check_out >= today
      );

      await conn.query(`
        UPDATE room
        SET
          check_in_and_out_soogie = ?,
          is_soogie = ?
        WHERE id = ?
      `, [
        JSON.stringify(filtered),
        filtered.length ? 1 : 0,
        room.id
      ]);
    }

   

    const normalize = (str) =>
      (str || "")
        .replace(/[^가-힣a-zA-Z0-9]/g, "")
        .toLowerCase();
    
    const normalizeProduct = (str) => {
      const normalized = normalize(str);

      if (normalized.includes("오페라")) {
        return "오페라글램핑";
      }

      return normalized;
    };

    // =====================================================
    // 0️⃣ 초기화
    // =====================================================
    await conn.query(`
      UPDATE room_group
      SET check_in_and_out = JSON_ARRAY()
    `);

    await conn.query(`
      UPDATE room
      SET
        is_soogie = 0,
        is_active = 1,
        available = 1,
        reason = NULL,
        disable_start = NULL,
        disable_end = NULL,
        check_in = NULL,
        check_out = NULL,
        check_in_and_out = JSON_ARRAY()
      WHERE is_soogie = 1
        AND disable_end < NOW()
    `);

    // =====================================================
    // 1️⃣ 그룹 조회
    // =====================================================
    const [groups] = await conn.query(`
      SELECT id, name
      FROM room_group
      WHERE is_active = 1
    `);

    // =====================================================
    // 2️⃣ 예약 조회
    // =====================================================
    const [bookings] = await conn.query(`
      SELECT booking_id, product_name, check_in, check_out
      FROM naver_bookings
      WHERE cancel_date2 IS NULL
        AND check_out >= DATE_SUB(CURDATE(), INTERVAL 1 DAY)
      ORDER BY check_in ASC, created_at ASC
    `);

    const groupedDates = {};

    for (const group of groups) {
      groupedDates[group.id] = [];
    }

    for (const booking of bookings) {
      const product = normalizeProduct(booking.product_name);

      const group = groups.find((g) => {
        const gname = normalize(g.name);
        return product.includes(gname) || gname.includes(product);
      });

      if (!group) continue;

      groupedDates[group.id].push({
        check_in: toKSTDate(booking.check_in),
        check_out: toKSTDate(booking.check_out),
      });
    }

    // =====================================================
    // 3️⃣ room_group 저장
    // =====================================================
    for (const groupId in groupedDates) {
      await conn.query(`
        UPDATE room_group
        SET check_in_and_out = ?
        WHERE id = ?
      `, [
        JSON.stringify(groupedDates[groupId]),
        groupId
      ]);
    }

    // =====================================================
    // 4️⃣ room 배정
    // =====================================================
    for (const groupId in groupedDates) {
      const periods = groupedDates[groupId];

      const [rooms] = await conn.query(`
        SELECT id
        FROM room
        WHERE room_group_id = ?
        ORDER BY id ASC
      `, [groupId]);

      const roomSchedules = new Map();

      for (const room of rooms) {
        roomSchedules.set(room.id, []);
      }

      // 예약 배정
      for (const period of periods) {
        const start = period.check_in;
        const end = period.check_out;

        for (const room of rooms) {
          const schedule = roomSchedules.get(room.id);

          const overlap = schedule.some((s) =>
            start <= s.check_out &&
            s.check_in <= end
          );

          if (!overlap) {
            schedule.push({
              check_in: start,
              check_out: end,
              source:"naver"
            });
            break;
          }
        }
      }

      // =====================================================
      // 5️⃣ room별 저장
      // =====================================================
      for (const room of rooms) {
        const schedule = roomSchedules.get(room.id);

        if (!schedule.length) continue;

        schedule.sort((a, b) =>
          a.check_in.localeCompare(b.check_in)
        );

        const first = schedule[0];

        await conn.query(`
          UPDATE room
          SET
            is_active = 0,
            available = 0,
            disable_start = ?,
            disable_end = ?,
            check_in = ?,
            check_out = ?,
            check_in_and_out = ?,
            is_ota = 1
          WHERE id = ?
        `, [
          first.check_in,
          first.check_out,
          first.check_in,
          first.check_out,
          JSON.stringify(schedule),
          room.id
        ]);
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

// 10분 주기 실행
let isSyncing = false;

setInterval(async () => {
  if (isSyncing) return;
  isSyncing = true;

  try {
    await syncNaverBookingsToRooms();
  } finally {
    isSyncing = false;
  }
}, 1000 * 60 * 10);

// 초기 1회 실행
syncNaverBookingsToRooms();


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
    const [rows] = await pool.query(`SELECT * FROM naver_bookings ORDER BY id ASC`);
    const [rows2] = await pool.query(`SELECT * FROM room_group ORDER BY id ASC`);
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

export default app;
