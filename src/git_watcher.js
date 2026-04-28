// watcher.js
import { exec } from "child_process";

const BACKEND_DIR = "C:\\mnm\\backend";
const FRONTEND_DIR = "C:\\dreampingFront\\theDreampingFront";

// 중복 실행 방지
let backendRunning = false;
let frontendRunning = false;

// --- 백엔드 감시 ---
setInterval(() => {
if (backendRunning) return; // 이미 배포 중이면 스킵

exec(`cd /d ${BACKEND_DIR} && git fetch && git status -uno`, (err, stdout) => {
if (err) return console.error("Backend git fetch error:", err);

if (stdout.includes("Your branch is behind")) {
console.log("백엔드 새 커밋 감지 → auto_start.bat 실행");
backendRunning = true;
exec(`${BACKEND_DIR}\\auto_start.bat`, (err, stdout, stderr) => {
if (err) console.error("Backend auto_start.bat error:", err);
else console.log(stdout);

backendRunning = false; // 실행 완료 후 플래그 리셋
});
}
});
}, 300000); // 5분마다 체크

// --- 프론트엔드 감시 ---
setInterval(() => {
if (frontendRunning) return; // 이미 빌드 중이면 스킵

exec(`cd /d ${FRONTEND_DIR} && git fetch && git status -uno`, (err, stdout) => {
if (err) return console.error("Frontend git fetch error:", err);

if (stdout.includes("Your branch is behind")) {
console.log("프론트 새 커밋 감지 → auto_build.bat 실행");
frontendRunning = true;
exec(`${FRONTEND_DIR}\\auto_build.bat`, (err, stdout, stderr) => {
if (err) console.error("Frontend auto_build.bat error:", err);
else console.log(stdout);

frontendRunning = false; // 실행 완료 후 플래그 리셋
});
}
});
}, 300000); // 5분마다 체크