@echo off
echo ========================================
echo Starting CryptoVault Web Interface
echo ========================================
echo.
echo Installing dependencies...
py -m pip install Flask -q
echo.
echo Starting web server...
echo.
echo Open in browser: http://localhost:5000
echo.
echo Press Ctrl+C to stop
echo.
py app.py
pause

