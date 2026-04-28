import "dotenv/config";
import app from "./app.js";
import https from "https";
import fs from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

// __dirname 대체 코드
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const HTTPS_PORT = Number(process.env.HTTPS_PORT || 4000);

// 인증서 파일 경로 (dirname 기준)



const key = fs.readFileSync("C:/cert/dreampingback.duckdns.org-key.pem", "utf8");
const cert = fs.readFileSync("C:/cert/dreampingback.duckdns.org-chain.pem", "utf8");

https.createServer({ key, cert }, app).listen(HTTPS_PORT, "0.0.0.0", () => {
  console.log(`HTTPS server listening at https://localhost:${HTTPS_PORT}`);
});
