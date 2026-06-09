@echo off
python -m venv .venv
call .venv\Scripts\activate
pip install -r requirements.txt
if not exist reports mkdir reports
if not exist logs mkdir logs
echo SOC AutoPilot setup complete
