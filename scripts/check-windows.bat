@echo off
setlocal
pushd "%~dp0.." || exit /b 1
cargo fmt --check || goto :fail
cargo clippy --locked --all-targets -- -D warnings || goto :fail
cargo test --locked || goto :fail
cargo build --locked || goto :fail
python tests\setup.py || goto :fail
python tests\https.py || goto :fail
python tests\mtls.py || goto :fail
python tests\psk.py || goto :fail
popd
exit /b 0
:fail
popd
exit /b 1
