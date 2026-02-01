import { Router } from "express";
import {
  listUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
  sendOtp,
  verifyOtp,
  sendOtpNaver,
  verifyBusinessNumber,
  createUser2,
  requestTwilloNumber,
  verifyTwilloNumber,
  loginUser,
  loginUser2,
  //  tokenReissue,
  logoutUser,
  login,
} from "../controllers/user.controller.js";

import verifyToken from "../middlewares/verifyToken.js";

import multer from "multer";
import path from "path";

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

const router = Router();

router.get("/", listUsers); // GET    /api/users
router.get("/:id", getUser); // GET    /api/users/:id
router.post("/", createUser); // POST   /api/users
router.post(
  "/eul",
  upload.fields([
    { name: "document_01", maxCount: 1 },
    { name: "document_02", maxCount: 1 },
    { name: "document_03", maxCount: 1 },
  ]),
  createUser2,
); // POST   /api/users
router.patch("/:id", updateUser); // PATCH  /api/users/:id
router.delete("/:id", deleteUser); // DELETE /api/users/:id
router.post("/send-otp", sendOtp); // POST   /api/send-otp
router.post("/send-otp-naver", sendOtpNaver); // POST   /api/users/send-otp-naver
router.post("/verify-otp", verifyOtp); // POST   /api/verify-otp
router.post("/verify-business", verifyBusinessNumber);
router.post("/send-otp-twillo", requestTwilloNumber);
router.post("/verify-twillo-otp-number", verifyTwilloNumber);
router.post("/garp/login", loginUser);
router.post("/login", login);
router.post("/eul/login", loginUser2);
//router.post("/token/reissue", verifyToken, tokenReissue);
router.post("/logout", verifyToken, logoutUser);

export default router;
