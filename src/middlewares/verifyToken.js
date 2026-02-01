import jwt from "jsonwebtoken"; // 💡 jwt 임포트 빼먹지 마세요!

export default function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  // "Bearer TOKEN_VALUE" 형태에서 TOKEN_VALUE만 쏙 뽑아내기
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(403).json({ message: "토큰이 없어!" });

  jwt.verify(token, process.env.JWT_ACCESS_SECRET, (err, decoded) => {
    if (err) {
      // 여기서 401을 줘야 클라이언트 api.js가 "아, 만료됐구나!" 하고 재발급을 시도해요!
      return res.status(401).json({ message: "유효하지 않은 토큰이야!" });
    }

    req.user = decoded;
    next();
  });
}
