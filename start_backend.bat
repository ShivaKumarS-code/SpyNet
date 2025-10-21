@echo off
echo Starting SpyNet Integrated System...
cd backend

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate

REM Install/update requirements
echo Installing requirements...
pip install -r requirements.txt

REM Create logs directory
if not exist "logs" mkdir logs

REM Start the integrated SpyNet system
echo Starting SpyNet Network Intrusion Detection System...
echo.
echo Web interface will be available at: http://localhost:8000
echo API documentation at: http://localhost:8000/docs
echo.
python run_spynet.py