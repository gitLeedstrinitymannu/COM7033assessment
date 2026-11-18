# COM7033 Assessment

## Project Overview

This repository contains the COM7033 assessment project: a secure Student Support
Case Management System built with Python and Flask.

## Development Environment

- Python
- Git and GitHub
- Python Virtual Environment

## Databases

- **SQLite**: relational data (built into Python, file created automatically in `instance/`)
- **MongoDB**: document data (needs a running MongoDB server or a MongoDB Atlas URI)

## Setup

1. Create and activate a virtual environment
   - Windows: `python -m venv venv` then `venv\Scripts\activate`
   - Mac/Linux: `python3 -m venv venv` then `source venv/bin/activate`
2. `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and fill in the values
4. Start MongoDB locally (or put your Atlas URI in `MONGO_URI`)
5. `python app.py`
6. Open http://127.0.0.1:5001/api/db-status. Both databases should show `connected`

## Security

Environment variables and local database files are excluded from version control.
