@echo off
python "%~dp0pki.py" server %*
exit /b %errorlevel%
