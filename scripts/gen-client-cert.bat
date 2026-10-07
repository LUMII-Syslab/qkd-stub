@echo off
python "%~dp0pki.py" client %*
exit /b %errorlevel%
