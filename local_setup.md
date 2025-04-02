# VAPT Report Generator - Local Setup Guide

## Basic Setup

1. Clone or download the repository
2. Create a virtual environment: `python -m venv venv`
3. Activate it:
   - Linux/Mac: `source venv/bin/activate`
   - Windows: `venv\Scripts\activate`
4. Install the basic requirements: `pip install flask flask-sqlalchemy gunicorn python-docx reportlab sqlalchemy psycopg2-binary werkzeug email-validator`
5. Run the application: `python main.py`

## PDF Generation Options

The application uses two different libraries for PDF generation:

1. **ReportLab** (always available): Used for the main PDF generation
2. **WeasyPrint** (optional): Used for HTML-to-PDF conversion

If you encounter this error:
```
OSError: cannot load library 'gobject-2.0-0': error 0x7e
```

You have two options:

### Option 1: Install GTK Dependencies (for full WeasyPrint functionality)

#### For Windows:
1. Download and install the GTK3 runtime from: [GTK for Windows Runtime Environment Installer](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases)
2. Make sure to add the GTK path to your system PATH during installation
3. Install WeasyPrint: `pip install weasyprint`

#### For macOS:
```
brew install gtk+3 pygobject3 libffi
pip install weasyprint
```

#### For Ubuntu/Debian:
```
sudo apt-get install build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
pip install weasyprint
```

### Option 2: Use Only ReportLab (no extra setup required) - RECOMMENDED FOR WINDOWS

The application is configured to use only ReportLab by default, which doesn't require GTK libraries. All PDF generation functionality works without WeasyPrint.

If you want to enable WeasyPrint (optional):
1. First install the GTK dependencies as described in Option 1
2. Open `utils.py` and uncomment the WeasyPrint import block
3. Set `WEASYPRINT_AVAILABLE = True`

## Database Setup

The application uses SQLite by default. If you want to use PostgreSQL:

1. Install PostgreSQL on your system
2. Create a database for the application
3. Set the `DATABASE_URL` environment variable to your PostgreSQL connection string:
   - Linux/Mac: `export DATABASE_URL=postgresql://username:password@localhost/dbname`
   - Windows: `set DATABASE_URL=postgresql://username:password@localhost/dbname`

## Troubleshooting

- If you encounter any issues with database connections, check that the database URL is correctly formatted
- For PDF generation issues, ensure you have the correct dependencies installed based on your chosen PDF generation option
- If you're having trouble with image uploads, check that the directory permissions allow writing to the database file