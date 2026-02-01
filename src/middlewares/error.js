export default function errorMiddleware(err, req, res, next) {
  console.error(err);
  const status = err.status || 500;
  const message = err.message || "Internal Server Error";
  res.status(status).json({
    message,
    // 개발 중에는 에러 스택을 보고 싶을 수 있습니다.
    // 프로덕션에서는 제거하세요.
    ...(process.env.NODE_ENV !== "production" && { stack: err.stack }),
  });
}
