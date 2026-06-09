@echo off
python -m venv .venv
call .venv\Scripts\activate
pip install -r requirements.txt
if not exist reports mkdir reports
if not exist logs mkdir logs
if not exist .env (
    copy .env.example .env >nul
    echo Created .env from .env.example — add your API keys before running.
)
echo SOC AutoPilot setup complete
