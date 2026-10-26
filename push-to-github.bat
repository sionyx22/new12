@echo off
chcp 65001 >nul
setlocal
set "SRC=%~dp0"
set "TMP_DIR=%TEMP%\pccleaner-push"
findstr /C:"VERSION = \"8.3\"" "%SRC%main.py" >nul || (echo main.py is not version 8.3 & pause & exit /b 1)
where git >nul 2>nul || (echo git is not installed & pause & exit /b 1)
echo Paste the GitHub token for sionyx22 and press Enter:
set /p TOKEN=
if "%TOKEN%"=="" (echo No token entered & pause & exit /b 1)
if exist "%TMP_DIR%" rmdir /s /q "%TMP_DIR%"
mkdir "%TMP_DIR%"
xcopy "%SRC%*" "%TMP_DIR%\" /E /I /Y /Q >nul
if exist "%TMP_DIR%\push-to-github.bat" del "%TMP_DIR%\push-to-github.bat"
cd /d "%TMP_DIR%"
git init -q
git config user.name "sionyx22"
git config user.email "sionyx22@users.noreply.github.com"
git add .
git commit -q -m "v8.3"
git branch -M main
git -c credential.helper= push https://sionyx22:%TOKEN%@github.com/sionyx22/new12.git main
if errorlevel 1 (
  echo.
  echo Push rejected. The repo is new, so you can override. Press any key to force-push.
  pause >nul
  git -c credential.helper= push https://sionyx22:%TOKEN%@github.com/sionyx22/new12.git main --force
  if errorlevel 1 (echo FAILED & cd /d "%SRC%" & pause & exit /b 1)
)
cd /d "%SRC%"
rmdir /s /q "%TMP_DIR%"
set TOKEN=
echo DONE
pause
