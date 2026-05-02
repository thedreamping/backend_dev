import "dotenv/config";
import app from "./app.js";
import https from "https";
import fs from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const HTTPS_PORT = Number(process.env.HTTPS_PORT || 4000);
const SSL_MODE = process.env.SSL_MODE || "local";

let key;
let cert;

if (SSL_MODE === "aws") {
  key = fs.readFileSync(
    "C:/cert/dreampingback.duckdns.org-key.pem",
    "utf8"
  );

  cert = fs.readFileSync(
    "C:/cert/dreampingback.duckdns.org-chain.pem",
    "utf8"
  );

  console.log("🟢 AWS SSL loaded");
} else {
  key = fs.readFileSync(
    join(__dirname, "localhost-key.pem"),
    "utf8"
  );

  cert = fs.readFileSync(
    join(__dirname, "localhost.pem"),
    "utf8"
  );

  console.log("🟢 Local SSL loaded");
}

https.createServer({ key, cert }, app).listen(
  HTTPS_PORT,
  "0.0.0.0",
  () => {
    console.log(`HTTPS server listening on port ${HTTPS_PORT}`);
  }
);