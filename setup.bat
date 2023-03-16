@echo off
python --version
IF %errorlevel%==0 (
    pip install -r requirements.txt
) ELSE (
    echo Missing Python Enviroment
)