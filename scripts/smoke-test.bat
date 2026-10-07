@echo off
python "%~dp0smoke-test.py" %*
exit /b %errorlevel%
