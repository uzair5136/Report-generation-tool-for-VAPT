# VAPT Report Generator

This web application streamlines the process of creating comprehensive Vulnerability Assessment and Penetration Testing (VAPT) reports. It allows security professionals to document their findings in a standardized format and export professional reports in both PDF and editable DOCX formats.

## Features

- Create and manage vulnerability reports for web or mobile applications
- Add detailed vulnerability information with severity levels
- Upload screenshot evidence of vulnerabilities
- Generate professional PDF reports with custom formatting
- Export reports in editable DOCX format
- Dashboard for managing multiple reports

## How to Download This Project

Since downloading directly as a ZIP file might be challenging in your current environment, follow these steps to get the code:

1. **View the export instructions file**:
   - Open `export_instructions.md` in this project
   - This file contains all the code needed to recreate the project locally

2. **Copy the code to your local machine**:
   - Create the folder structure as described in the export instructions
   - Copy and paste each file's content from the export instructions document
   - Make sure to create all template files (HTML) and static files (CSS/JS)

3. **Setup a local environment**:
   - Follow the instructions in `local_setup.md` for detailed steps
   - This includes handling optional dependencies like WeasyPrint
   - Initialize the database
   - Run the application

4. **Troubleshooting local setup**:
   - If you encounter the `gobject-2.0-0` error, see the solutions in `local_setup.md`
   - The application is designed to work without WeasyPrint if the GTK dependencies are not available

## Usage

1. Create a new report by providing client and project details
2. Add vulnerabilities with descriptions, severity levels, impacts, and remediation recommendations
3. Upload evidence screenshots for each vulnerability
4. Preview the report before exporting
5. Export as PDF for client delivery or DOCX for further editing

## Recent Updates

- Updated the report template to match professional VAPT report standards
- Added new sections in the reports including Engagement Overview, Service Description, and Client Details
- Improved the Executive Summary section with more professional language
- Enhanced the Table of Contents with better formatting
- Standardized the approach section with bullet points for better readability

## Technologies Used

- Flask (Python web framework)
- SQLAlchemy (ORM for database)
- ReportLab (PDF generation - primary)
- WeasyPrint (HTML-to-PDF conversion - optional)
- Python-docx (DOCX generation)
- Bootstrap (Frontend)

## System Requirements

- Python 3.7+
- For full functionality with WeasyPrint:
  - Windows: GTK3 runtime
  - macOS: gtk+3, pygobject3, libffi
  - Linux: Various GTK libraries (see local_setup.md)
- Basic functionality works without these dependencies