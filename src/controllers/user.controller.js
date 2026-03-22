import pool from "../db.js";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import fetch from "node-fetch";
import twilio from "twilio";
import jwt from "jsonwebtoken";

// 1. 클라이언트는 파일 상단에서 한 번만 초기화
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const sender = process.env.TWILIO_PHONE_NUMBER;
const client = twilio(accountSid, authToken);

const otpStore = new Map();

export const requestTwilloNumber = async (req, res) => {
  try {
    let { phoneNumber, countryCode } = req.body;

    // 국가코드 전처리 (+ 중복 방지)
    const cleanCountryCode = countryCode.toString().replace("+", "");
    const fullNumber = `+${cleanCountryCode}${phoneNumber}`;

    // 1. 형식 체크 (간단한 정규식)
    if (!/^\+\d{10,15}$/.test(fullNumber)) {
      return res
        .status(400)
        .json({ message: "Invalid international phone format." });
    }

    // [도배 방지]
    const existing = otpStore.get(fullNumber);
    if (
      existing &&
      existing.blockedUntil &&
      Date.now() < existing.blockedUntil
    ) {
      return res.status(429).json({ error: "Too many requests. Try later." });
    }

    // 2. OTP 생성 및 해싱
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const hash = await bcrypt.hash(otp, 10);
    const ttlMs = 3 * 60 * 1000;

    // 3. 트윌로 발송 (상단에 선언된 client 사용)
    const isSent = await sendOtpSmsTwilio(fullNumber, otp);

    if (isSent) {
      otpStore.set(fullNumber, {
        hash,
        expiresAt: Date.now() + ttlMs,
        attempts: 0,
      });
      // console.log(`[Twilio] OTP for ${fullNumber}: ${otp}`); // 개발용
      return res
        .status(200)
        .json({ success: true, message: "OTP sent.", expiresIn: ttlMs / 1000 });
    } else {
      return res.status(500).json({ message: "SMS delivery failed." });
    }
  } catch (error) {
    console.error("Twilio Request Error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

export const sendOtpSmsTwilio = async (phone, otp) => {
  try {
    const message = await client.messages.create({
      body: `[Made It] Your code is ${otp}. Valid for 3 mins.`,
      from: sender,
      to: phone,
    });
    return !!message.sid;
  } catch (err) {
    console.error("Twilio SMS error:", err);
    return false;
  }
};

export const verifyTwilloNumber = async (req, res) => {
  try {
    const { phoneNumber, countryCode, otpCode } = req.body;

    // 1. 필수값 체크
    if (!phoneNumber || !countryCode || !otpCode) {
      return res.status(400).json({
        message: "Phone number, country code, and code are required.",
      });
    }
    const cleanCountryCode = countryCode.toString().replace("+", "");
    const fullNumber = `+${cleanCountryCode}${phoneNumber}`;

    // 2. otpStore에서 데이터 가져오기 (형이 아까 만든 Map)
    const item = otpStore.get(fullNumber);

    if (!item) {
      return res.status(400).json({ message: "No OTP requested or expired." });
    }

    // 3. 만료 시간 확인
    if (Date.now() > item.expiresAt) {
      otpStore.delete(fullNumber);
      return res.status(400).json({ message: "OTP expired." });
    }

    // 4. 시도 횟수 제한 (어뷰징 방지)
    item.attempts = (item.attempts || 0) + 1;
    if (item.attempts > 5) {
      item.blockedUntil = Date.now() + 60 * 60 * 1000; // 1시간 차단
      otpStore.set(fullNumber, item);
      return res
        .status(429)
        .json({ message: "Too many attempts. Account blocked for 1 hour." });
    }

    // 5. bcrypt로 번호 비교
    const match = await bcrypt.compare(otpCode, item.hash);
    if (!match) {
      otpStore.set(fullNumber, item); // 시도 횟수 업데이트를 위해 다시 저장
      return res.status(400).json({ message: "Invalid verification code." });
    }

    // 6. 인증 성공!
    otpStore.delete(fullNumber); // 재사용 방지를 위해 즉시 삭제

    return res.status(200).json({
      success: true,
      message: "Phone number verified successfully!",
    });
  } catch (error) {
    console.error("VerifyTwilloNumber Error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
};

// 네이버 SENS 인증 헤더 생성
function makeSignature({ method, url, timestamp, accessKey, secretKey }) {
  const space = " ";
  const newLine = "\n";
  const message = [
    method,
    space,
    url,
    newLine,
    timestamp,
    newLine,
    accessKey,
  ].join("");

  const hmac = crypto.createHmac("sha256", secretKey);
  hmac.update(message);
  return hmac.digest("base64");
}

// OTP 발송
export const sendOtpSmsNaver = async (phone, otp) => {
  try {
    const serviceId = process.env.NCP_SENS_SERVICE_ID; // SENS 서비스 ID
    const accessKey = process.env.NCP_ACCESS_KEY;
    const secretKey = process.env.NCP_SECRET_KEY;
    const sender = process.env.NCP_SENS_SENDER; // 발신번호(네이버 콘솔에서 등록)

    const method = "POST";
    const url = `/sms/v2/services/${serviceId}/messages`;
    const apiUrl = `https://sens.apigw.ntruss.com${url}`;
    const timestamp = Date.now().toString();

    const signature = makeSignature({
      method,
      url,
      timestamp,
      accessKey,
      secretKey,
    });

    const body = {
      type: "SMS",
      contentType: "COMM",
      countryCode: "82", // 한국: 82
      from: sender,
      content: `[서비스명] 인증번호 ${otp}
본인 확인용이며 3분간 유효합니다.`,
      messages: [{ to: phone }],
    };

    const response = await fetch(apiUrl, {
      method,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "x-ncp-apigw-timestamp": timestamp,
        "x-ncp-iam-access-key": accessKey,
        "x-ncp-apigw-signature-v2": signature,
      },
      body: JSON.stringify(body),
    });

    const data = await response.json();
    if (response.ok) {
      console.log("Naver SMS sent:", data);
      return true;
    } else {
      console.error("Naver SMS error:", data);
      return false;
    }
  } catch (err) {
    console.error("Naver SMS send error:", err);
    return false;
  }
};

function generateOtp(length = 6) {
  // 0-padded 숫자 OTP
  const max = 10 ** length;
  const n = crypto.randomInt(0, max);
  return n.toString().padStart(length, "0");
}

export const sendOtp = async (req, res) => {
  if (req.method !== "POST") return res.status(405).end();

  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: "phone required" });

  // rate limiting (간단 예시)
  const existing = otpStore.get(phone);
  if (existing && existing.blockedUntil && Date.now() < existing.blockedUntil) {
    return res.status(429).json({ error: "Too many requests. Try later." });
  }

  const otp = generateOtp(6);
  const saltRounds = 10;
  const hash = await bcrypt.hash(otp, saltRounds);
  const ttlMs = 3 * 60 * 1000; // 3분

  otpStore.set(phone, {
    hash,
    expiresAt: Date.now() + ttlMs,
    attempts: 0,
  });

  const smsSent = await sendOtpSms(phone, otp);
  if (!smsSent) return res.status(500).json({ error: "SMS send failed" });
  console.log(
    `SEND OTP to ${phone}: ${otp} (dev only - do not log in production)`,
  );

  return res.json({ ok: true, expiresIn: ttlMs / 1000 });
};

export const sendOtpNaver = async (req, res) => {
  if (req.method !== "POST") return res.status(405).end();

  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: "phone required" });

  const existing = otpStore.get(phone);
  if (existing && existing.blockedUntil && Date.now() < existing.blockedUntil) {
    return res.status(429).json({ error: "Too many requests. Try later." });
  }

  const otp = generateOtp(6);
  const hash = await bcrypt.hash(otp, 10);
  const ttlMs = 3 * 60 * 1000; // 3분

  otpStore.set(phone, {
    hash,
    expiresAt: Date.now() + ttlMs,
    attempts: 0,
  });

  // --- 여기서 네이버 SENS 호출 ---
  const smsSent = await sendOtpSmsNaver(phone, otp);
  if (!smsSent) return res.status(500).json({ error: "SMS send failed" });

  console.log(
    `SEND OTP to ${phone}: ${otp} (dev only - do not log in production)`,
  );

  return res.json({ ok: true, expiresIn: ttlMs / 1000 });
};

const client2 = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

export const sendOtpSms = async (phone, otp) => {
  try {
    const message = await client2.messages.create({
      body: `Your OTP code: ${otp}`,
      from: process.env.TWILIO_PHONE, // Twilio에서 발급받은 번호
      to: phone,
    });
    console.log("SMS sent:", message.sid);
    return true;
  } catch (err) {
    console.error("SMS send error:", err);
    return false;
  }
};

// otp 인증
const otpStore2 = otpStore || new Map();

export const verifyOtp = async (req, res) => {
  if (req.method !== "POST") return res.status(405).end();
  const { phone, code } = req.body;
  if (!phone || !code)
    return res.status(400).json({ error: "phone and code required" });

  const item = otpStore2.get(phone);
  if (!item)
    return res.status(400).json({ error: "No OTP requested or expired" });

  if (Date.now() > item.expiresAt) {
    otpStore2.delete(phone);
    return res.status(400).json({ error: "OTP expired" });
  }

  // 시도 제한
  item.attempts = (item.attempts || 0) + 1;
  if (item.attempts > 5) {
    item.blockedUntil = Date.now() + 60 * 60 * 1000; // 1시간 차단
    otpStore2.set(phone, item);
    return res.status(429).json({ error: "Too many attempts" });
  }

  const match = await bcrypt.compare(code, item.hash);
  if (!match) {
    otpStore2.set(phone, item);
    return res.status(400).json({ error: "Invalid code" });
  }

  // 성공: 인증 처리 (예: DB에 인증 플래그, JWT 발급 등)
  otpStore2.delete(phone); // 재사용 금지

  // 예: JWT 발급 (간단 예)
  // const token = signJwt({ phone }, process.env.JWT_SECRET, { expiresIn: '30d' });

  return res.json({ ok: true /*, token */ });
};

// 유틸: 페이징 파라미터 정리
function parsePaging(query) {
  const page = Math.max(1, parseInt(query.page ?? "1", 10));
  const limit = Math.min(100, Math.max(1, parseInt(query.limit ?? "20", 10)));
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}

export const listUsers = async (req, res) => {
  const { limit, offset } = parsePaging(req.query);

  // (선택) 키워드 검색
  const keyword = (req.query.q || "").trim();
  const where = [];
  const params = [];

  if (keyword) {
    where.push("(name LIKE ? OR email LIKE ?)");
    params.push(`%${keyword}%`, `%${keyword}%`);
  }

  const whereSQL = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const [rows] = await pool.query(
    `SELECT id, name, email, created_at
     FROM member_garp
     ${whereSQL}
     ORDER BY id DESC
     LIMIT ? OFFSET ?`,
    [...params, limit, offset],
  );

  const [[{ total }]] = await pool.query(
    `SELECT COUNT(*) AS total FROM member_garp ${whereSQL}`,
    params,
  );

  res.json({
    total,
    page: Math.floor(offset / limit) + 1,
    limit,
    items: rows,
  });
};

//사업자등록번호 유효성 검증
const isValidBizNo = (bizNo) => {
  const num = bizNo.replace(/[^0-9]/g, "");

  if (num.length !== 10) return false;

  const weights = [1, 3, 7, 1, 3, 7, 1, 3, 5];
  let sum = 0;

  for (let i = 0; i < 9; i++) {
    sum += Number(num[i]) * weights[i];
  }

  sum += Math.floor((Number(num[8]) * 5) / 10);

  return (10 - (sum % 10)) % 10 === Number(num[9]);
};

//사업자 번호 인증
export const checkNtsBusinessStatus = async (businessNumber) => {
  try {
    const serviceKey = process.env.NTS_SERVICE_KEY;

    if (!serviceKey) {
      console.error("❌ NTS_SERVICE_KEY 없음");
      return {
        valid: false,
        message: "국세청 서비스 키가 설정되지 않았습니다.",
      };
    }

    const url =
      "https://api.odcloud.kr/api/nts-businessman/v1/status?serviceKey=" +
      serviceKey;

    const body = {
      b_no: [businessNumber.replace(/[^0-9]/g, "")],
    };

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json", // ★ 중요
      },
      body: JSON.stringify(body),
    });

    // ✅ HTTP 에러 방어 (이게 핵심)
    if (!response.ok) {
      const text = await response.text();
      console.error("❌ NTS HTTP Error:", response.status, text);

      return {
        valid: false,
        message: "국세청 API 응답 오류",
      };
    }

    const data = await response.json();

    // ✅ 응답 구조 방어
    if (!Array.isArray(data.data) || !data.data[0]) {
      return {
        valid: false,
        message: data.message || "사업자 정보 조회 실패",
      };
    }

    const info = data.data[0];

    if (info.b_stt !== "계속사업자") {
      return {
        valid: false,
        status: info.b_stt,
        message: `사업자 상태: ${info.b_stt}`,
      };
    }

    return {
      valid: true,
      status: info.b_stt,
      taxType: info.tax_type,
      companyName: info.b_nm,
    };
  } catch (err) {
    console.error("❌ NTS API catch error:", err);
    return {
      valid: false,
      message: "국세청 조회 중 서버 오류",
    };
  }
};

//사업자 번호 인증 본체
export const verifyBusinessNumber = async (req, res) => {
  try {
    const { businessNumber } = req.body;

    if (!businessNumber) {
      return res.status(400).json({
        message: "businessNumber required",
      });
    }

    if (!isValidBizNo(businessNumber)) {
      return res.status(400).json({
        message: "유효하지 않은 사업자등록번호 형식입니다.",
      });
    }

    const result = await checkNtsBusinessStatus(businessNumber);

    // ❗ 여기서도 방어
    if (!result || !result.valid) {
      return res.status(400).json({
        message: result?.message || "사업자 확인 실패",
      });
    }

    return res.json({
      ok: true,
      status: result.status,
      companyName: result.companyName,
    });
  } catch (err) {
    console.error("❌ verifyBusinessNumber error:", err);

    return res.status(500).json({
      message: "사업자번호 확인 중 서버 오류가 발생했습니다.",
    });
  }
};

export const getUser = async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ message: "Invalid id" });
  }

  const [rows] = await pool.query(
    "SELECT id, name, email, created_at FROM member_garp WHERE id = ?",
    [id],
  );
  if (rows.length === 0) {
    return res.status(404).json({ message: "User not found" });
  }
  res.json(rows[0]);
};

// 갑 회원 등록
export const createUser = async (req, res) => {
  try {
    const { name, admin_id, password } = req.body;

    const missingFields = [];
    if (!name) missingFields.push("name");
    if (!admin_id) missingFields.push("email_id");

    if (!password) missingFields.push("password");

    if (missingFields.length > 0) {
      return res
        .status(400)
        .json({ message: `Missing fields: ${missingFields.join(", ")}` });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      "INSERT INTO admin_users (name, adminId, password) VALUES (?, ?, ?)",
      [name, admin_id, hashedPassword],
    );

    const [rows] = await pool.query(
      "SELECT id, name, adminId, createdAt FROM admin_users WHERE id = ?",
      [result.insertId],
    );

    if (!rows[0])
      return res.status(500).json({ message: "User not found after insert" });

    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

// 을 회원 등록
export const createUser2 = async (req, res) => {
  try {
    // 1. 파일 경로 추출
    const doc01 = req.files?.["document_01"]?.[0]?.path || null;
    const doc02 = req.files?.["document_02"]?.[0]?.path || null;
    const doc03 = req.files?.["document_03"]?.[0]?.path || null;

    // 2. 데이터 추출
    const {
      name,
      email_id,
      nation,
      telephone,
      password,
      bizno,
      portfolio_url,
      introduce_kor,
      introduce_eng,
    } = req.body;

    // 3. 유효성 검사 (오타 수정 및 체크)
    const missingFields = [];
    if (!name) missingFields.push("name");
    if (!email_id) missingFields.push("email_id");
    if (!nation) missingFields.push("nation");
    if (!telephone) missingFields.push("telephone");
    if (!password) missingFields.push("password");
    if (!bizno) missingFields.push("bizno");
    if (!portfolio_url) missingFields.push("portfolio_url");
    // if (!introduce_kor) missingFields.push("introduce_kor");
    // if (!introduce_eng) missingFields.push("introduce_eng");

    // 파일이 필수일 경우만 체크 (필수가 아니면 아래 3줄 주석 처리)
    // if (!doc01) missingFields.push("document_01");
    // if (!doc02) missingFields.push("document_02");
    // if (!doc03) missingFields.push("document_03");

    if (missingFields.length > 0) {
      return res.status(400).json({
        message: `Missing fields: ${missingFields.join(", ")}`,
      });
    }

    // 4. 비밀번호 암호화
    const hashedPassword = await bcrypt.hash(password, 10);

    // 5. DB 데이터 삽입 (컬럼 12개, 값 12개 정확히 매칭)
    const query = `
      INSERT INTO member_eul (
        name, email_id, nation, telephone, password, 
        bizno, portfolio_url, document_01, document_02, 
        document_03, introduce_kor, introduce_eng
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    const values = [
      name,
      email_id,
      nation,
      telephone,
      hashedPassword,
      bizno,
      portfolio_url,
      doc01,
      doc02,
      doc03,
      introduce_kor,
      introduce_eng,
    ];

    const [result] = await pool.query(query, values);

    // 6. 결과 반환
    const [rows] = await pool.query(
      "SELECT id, name, email_id, created_at FROM member_garp WHERE id = ?",
      [result.insertId],
    );

    res.status(201).json(rows[0]);
  } catch (err) {
    console.error("Error in createUser2:", err);
    res.status(500).json({ message: "Server error" });
  }
};

export const updateUser = async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ message: "Invalid id" });
  }

  const { name, email } = req.body;
  // 부분 업데이트 가능
  const fields = [];
  const params = [];

  if (name !== undefined) {
    fields.push("name = ?");
    params.push(name);
  }
  if (email !== undefined) {
    fields.push("email = ?");
    params.push(email);
  }

  if (fields.length === 0) {
    return res.status(400).json({ message: "Nothing to update" });
  }

  params.push(id);

  const [result] = await pool.query(
    `UPDATE member_garp SET ${fields.join(", ")} WHERE id = ?`,
    params,
  );

  if (result.affectedRows === 0) {
    return res.status(404).json({ message: "User not found" });
  }

  const [rows] = await pool.query(
    "SELECT id, name, email, created_at FROM member_garp WHERE id = ?",
    [id],
  );
  res.json(rows[0]);
};

export const deleteUser = async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ message: "Invalid id" });
  }

  const [result] = await pool.query("DELETE FROM member_garp WHERE id = ?", [
    id,
  ]);
  if (result.affectedRows === 0) {
    return res.status(404).json({ message: "User not found" });
  }
  res.status(204).send(); // 내용 없음
};

// 토큰 발급 함수 (헬퍼)
const generateTokens = (user) => {
  const accessToken = jwt.sign(
    { id: user.id, email: user.email_id, role: user.role },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: "15m" }, // 억세스 토큰은 짧게!
  );

  const refreshToken = jwt.sign(
    { id: user.id },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" }, // 리프레쉬 토큰은 길게!
  );

  return { accessToken, refreshToken };
};

// 1. 갑(Garp) 로그인
export const loginUser = async (req, res) => {
  try {
    const { email_id, password } = req.body;

    // 사용자 확인
    const [rows] = await pool.query(
      "SELECT * FROM member_garp WHERE email_id = ?",
      [email_id],
    );

    const user = rows[0];
    if (!user) {
      return res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 틀렸습니다." });
    }

    // 비밀번호 체크
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 틀렸습니다." });
    }

    // 토큰 발급
    const { accessToken, refreshToken } = generateTokens({
      ...user,
      role: "garp",
    });

    res.status(200).json({
      message: "갑 로그인 성공!",
      accessToken,
      refreshToken,
      user: { id: user.id, name: user.name, email_id: user.email_id },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

// 1. 갑(Garp) 로그인
export const login = async (req, res) => {
  try {
    const { admin_id, password } = req.body;

    // 사용자 확인
    const [rows] = await pool.query(
      "SELECT * FROM admin_users WHERE adminId = ?",
      [admin_id],
    );

    const user = rows[0];
    if (!user) {
      return res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 틀렸습니다." });
    }

    // 비밀번호 체크
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 틀렸습니다." });
    }

    // 토큰 발급
    const { accessToken, refreshToken } = generateTokens({
      ...user,
      role: "admin",
    });

    res.status(200).json({
      message: "로그인 성공!",
      accessToken,
      refreshToken,
      user: { admin_id: user.adminId, adming_name: user.name },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

// 2. 을(Eul) 로그인
export const loginUser2 = async (req, res) => {
  try {
    const { email_id, password } = req.body;

    // 사용자 확인
    const [rows] = await pool.query(
      "SELECT * FROM member_eul WHERE email_id = ?",
      [email_id],
    );

    const user = rows[0];
    if (!user) {
      return res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 틀렸습니다." });
    }

    // 비밀번호 체크
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(401)
        .json({ message: "이메일 또는 비밀번호가 틀렸습니다." });
    }

    // 토큰 발급
    const { accessToken, refreshToken } = generateTokens({
      ...user,
      role: "eul",
    });

    res.status(200).json({
      message: "을 로그인 성공!",
      accessToken,
      refreshToken,
      user: { id: user.id, name: user.name, email_id: user.email_id },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
};

export const createAdminUser = async (req, res) => {
  try {
    const { name, adminId, password } = req.body;

    // 필수값 체크
    if (!name || !adminId || !password) {
      return res.status(400).json({
        message: "name, adminId, password are required",
      });
    }

    // 중복 adminId 체크
    const [existing] = await pool.query(
      "SELECT id FROM admin_users WHERE adminId = ?",
      [adminId],
    );

    if (existing.length > 0) {
      return res.status(409).json({
        message: "adminId already exists",
      });
    }

    // 비밀번호 암호화
    const hashedPassword = await bcrypt.hash(password, 10);

    // DB 저장
    const [result] = await pool.query(
      `INSERT INTO admin_users (name, adminId, password)
       VALUES (?, ?, ?)`,
      [name, adminId, hashedPassword],
    );

    // 생성된 관리자 조회
    const [rows] = await pool.query(
      `SELECT id, name, adminId, createdAt
       FROM admin_users
       WHERE id = ?`,
      [result.insertId],
    );

    res.status(201).json({
      message: "Admin user created",
      admin: rows[0],
    });
  } catch (err) {
    console.error("createAdminUser error:", err);
    res.status(500).json({ message: "Server error" });
  }
};
export const deleteAdminUser = async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        message: "Invalid admin id",
      });
    }

    const [result] = await pool.query("DELETE FROM admin_users WHERE id = ?", [
      id,
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({
        message: "Admin user not found",
      });
    }

    res.json({
      message: "Admin user deleted",
      id: id,
    });
  } catch (err) {
    console.error("deleteAdminUser error:", err);
    res.status(500).json({
      message: "Server error",
    });
  }
};
export const listAdminUsers = async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT id, name, adminId, createdAt
      FROM admin_users
      ORDER BY id DESC
    `);

    res.json({
      total: rows.length,
      items: rows,
    });
  } catch (err) {
    console.error("listAdminUsers error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

export const tokenReissue = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    // 1. 리프레시 토큰 체크
    if (!refreshToken) {
      return res.status(401).json({ message: "리프레시 토큰이 필요합니다." });
    }

    // 2. 토큰 검증
    jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET,
      async (err, decoded) => {
        if (err) {
          return res.status(403).json({
            message: "리프레시 토큰이 유효하지 않거나 만료되었습니다.",
          });
        }

        // 3. decoded 정보
        const { id } = decoded;

        // 4. admin_users 테이블에서 사용자 확인
        const [rows] = await pool.query(
          `SELECT * FROM admin_users WHERE id = ?`,
          [id],
        );

        const user = rows[0];
        if (!user) {
          return res
            .status(404)
            .json({ message: "관리자 사용자를 찾을 수 없습니다." });
        }

        // 5. 토큰 재발급
        const tokens = generateTokens({
          ...user,
          role: "admin", // 리조트는 고정
        });

        res.status(200).json({
          message: "토큰 재발급 성공",
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
        });
      },
    );
  } catch (err) {
    console.error("Token Reissue Error:", err);
    res.status(500).json({ message: "Server error" });
  }
};
export const logoutUser = async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      message: "서버 로그아웃 처리 완료! 클라이언트 토큰을 삭제하세요. 웅..!",
    });
  } catch (err) {
    console.error("Logout Error:", err);
    res
      .status(500)
      .json({ message: "로그아웃 처리 중 서버 오류가 발생했어요." });
  }
};
