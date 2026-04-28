@echo off




cd ..
cd mnm
cd backend
cd src


:: pm2 실행
start "" pm2 start git_watcher.js --name watcher_all
start "" pm2 save

:: Node.js 설치 경로 (본인 환경 확인)