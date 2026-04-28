@echo off
:: 1. 프로젝트 폴더로 이동
cd C:\mnm\backend

:: 2. 로컬 변경 사항 초기화 (필요하면)
git reset --hard HEAD

:: 3. 최신 커밋 가져오기
git pull origin main

:: 4. node_modules 설치/업데이트 (필요 시)
start "" cmd /k npm install

pause