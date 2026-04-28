@echo off




cd ..
cd mnm
cd backend

pm2 start src/server.js --name dreampingback --cwd "C:\mnm\backend"




