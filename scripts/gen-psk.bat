@echo off
python "%~dp0pki.py" psk %*
exit /b %errorlevel%
