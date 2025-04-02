# VAPT Report Generator - Export Instructions

This file contains the essential code for the VAPT Report Generator project. Follow the instructions below to recreate the project on your local machine.

## File Structure
```
/project_root
  ├── main.py
  ├── app.py
  ├── models.py
  ├── utils.py
  ├── static/
  │   ├── css/
  │   │   └── custom.css
  │   └── js/
  │       └── script.js
  ├── templates/
  │   ├── base.html
  │   ├── index.html
  │   ├── report_form.html
  │   ├── vulnerability_form.html
  │   ├── report_preview.html
  │   └── report_list.html
  └── requirements.txt
```

## Project Setup Instructions
1. Create the file structure above
2. Copy each file's content from this document
3. Create a virtual environment: `python -m venv venv`
4. Activate it: `source venv/bin/activate` (Linux/Mac) or `venv\Scripts\activate` (Windows)
5. Install the requirements: `pip install -r requirements.txt`
6. Initialize the database: `flask shell` then `db.create_all()` and `exit()`
7. Run the application: `python main.py`

## Requirements (requirements.txt)
```
flask==2.3.3
flask-sqlalchemy==3.1.1
gunicorn==21.2.0
python-docx==1.0.1
reportlab==4.0.7
sqlalchemy==2.0.23
weasyprint==60.2
psycopg2-binary==2.9.9
werkzeug==2.3.7
email-validator==2.1.0
```

## Python Files

### main.py
```python
from app import app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
```

### models.py
```python
from datetime import datetime
from app import db

class ClientInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contact_email = db.Column(db.String(100))
    contact_phone = db.Column(db.String(20))
    address = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    reports = db.relationship('Report', backref='client', lazy=True)
    
    def __repr__(self):
        return f"<Client {self.name}>"

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    domain_type = db.Column(db.String(20), nullable=False)  # Web or App
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    scope = db.Column(db.Text)
    approach = db.Column(db.Text)
    limitations = db.Column(db.Text)
    objectives = db.Column(db.Text)
    status = db.Column(db.String(20), default='Draft')  # Draft, Complete
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    client_id = db.Column(db.Integer, db.ForeignKey('client_info.id'), nullable=False)
    
    vulnerabilities = db.relationship('Vulnerability', backref='report', lazy=True, cascade='all, delete-orphan')
    images = db.relationship('Image', backref='report', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f"<Report {self.title}>"

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # Critical, High, Medium, Low
    impact = db.Column(db.Text)
    remediation = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    
    images = db.relationship('Image', backref='vulnerability', lazy=True)
    
    def __repr__(self):
        return f"<Vulnerability {self.title}>"

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.LargeBinary, nullable=False)  # Store image as binary data
    filename = db.Column(db.String(255))
    description = db.Column(db.Text)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerability.id'), nullable=True)
    
    def __repr__(self):
        return f"<Image {self.id}>"
```

### utils.py
```python
import io
import os
import base64
import tempfile
from datetime import datetime

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image as RLImage
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

# WeasyPrint for HTML-to-PDF conversion
import weasyprint

# Python-docx for Word document generation
from docx import Document
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH

def generate_report_pdf(report, vulnerabilities, client, stats, images):
    """Generate a PDF report based on the provided data"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    
    # Styles
    styles = getSampleStyleSheet()
    
    # Define custom styles or modify existing ones
    # Don't try to add styles that already exist
    styles['Heading1'].fontName = 'Helvetica-Bold'
    styles['Heading1'].fontSize = 18
    styles['Heading1'].spaceAfter = 12
    
    styles['Heading2'].fontName = 'Helvetica-Bold'
    styles['Heading2'].fontSize = 14
    styles['Heading2'].spaceAfter = 8
    
    # Add custom heading3 style only if it doesn't exist
    if 'Heading3' not in styles:
        styles.add(ParagraphStyle(name='Heading3',
                                fontName='Helvetica-Bold',
                                fontSize=12,
                                spaceAfter=6))
    
    # Modify Normal style
    styles['Normal'].fontName = 'Helvetica'
    styles['Normal'].fontSize = 10
    styles['Normal'].spaceAfter = 10
    
    # Title Page - Following the provided template
    elements.append(Paragraph("Vulnerability Assessment", styles['Heading1']))
    elements.append(Paragraph("and Penetration Testing", styles['Heading1']))
    elements.append(Spacer(1, 40))
    elements.append(Paragraph(f"{report.domain_type} Security Report", styles['Heading1']))
    elements.append(Paragraph("L1 Report", styles['Heading2']))
    elements.append(Paragraph(f"{datetime.now().strftime('%d %B %Y')}", styles['Heading2']))
    elements.append(PageBreak())
    
    # Engagement Overview
    elements.append(Paragraph("Engagement Overview", styles['Heading1']))
    engagement_text = f"""
    {client.name} has engaged our team to conduct a penetration test of their {report.domain_type}. 
    This report contains all the results of the assessment as well as all the action items that
    were included in the penetration test. The purpose of this report is to present the current
    security level of the external perimeters including gaps, vulnerabilities, and misconfigurations.
    The findings presented in this report should be fixed to improve the security level of the
    systems.
    """
    elements.append(Paragraph(engagement_text, styles['Normal']))
    elements.append(Spacer(1, 10))
    
    # Service Description
    elements.append(Paragraph("Service Description", styles['Heading1']))
    service_text = f"""
    {report.domain_type} Vulnerability Assessment and Penetration Testing (VAPT) is the process of
    simulating real-world attacks by using the same techniques as malicious hackers. For a
    security assessment that goes beyond a simple vulnerability scanner, you need experts in the
    industry. We conduct our penetration test by approaching the scope with both
    a manual and automatic approach.
    """
    elements.append(Paragraph(service_text, styles['Normal']))
    elements.append(Spacer(1, 10))
    
    # Web Application Penetration Test section
    elements.append(Paragraph(f"{report.domain_type} Penetration Test", styles['Heading1']))
    webapp_text = """
    Our application-level penetration testing consists of both unauthenticated and authenticated
    testing using both automated and manual methods with particular emphasis placed on
    identifying vulnerabilities associated with the OWASP Top 10 Most Critical Application
    Vulnerabilities. It is important to note that a penetration test is not just an automated
    vulnerability scan, and a large portion of web application penetration testing is a manual
    process with a skilled engineer attempting to identify, exploit, and evaluate the associate risk
    of security issues.
    """
    elements.append(Paragraph(webapp_text, styles['Normal']))
    elements.append(Spacer(1, 10))
    
    # Project Objectives
    elements.append(Paragraph("Project Objectives", styles['Heading1']))
    objectives_text = """
    We conduct all testing manually combined with custom and commercial tools that
    perform unique attack approaches on the network to make sure we cover the whole system in
    the test. Our expert knowledge and experience are the value we provide in our services.
    """
    elements.append(Paragraph(objectives_text, styles['Normal']))
    elements.append(Spacer(1, 10))
    
    # Client Details
    elements.append(Paragraph("Client Details", styles['Heading1']))
    client_details = [
        ["Organization", client.name],
        ["Contact Person", client.contact_phone or ""],
        ["Email id", client.contact_email or ""]
    ]
    client_table = Table(client_details, colWidths=[150, 250])
    client_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(client_table)
    elements.append(Spacer(1, 20))
    
    # Document Revision
    elements.append(Paragraph("Document Revision", styles['Heading1']))
    revision_details = [
        ["Version", "1.0"],
        ["Date", datetime.now().strftime('%d %B %Y')],
        ["Submitted By", "Security Team"]
    ]
    revision_table = Table(revision_details, colWidths=[150, 250])
    revision_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(revision_table)
    elements.append(Spacer(1, 20))
    
    # Test Performed Details
    elements.append(Paragraph("Test Performed Details", styles['Heading1']))
    test_details = [
        ["Testing done By", "Security Team"],
        ["Reviewed By", "Senior Security Analyst"],
        ["Date", f"{report.start_date.strftime('%d %B %Y')} - {report.end_date.strftime('%d %B %Y')}"],
        ["Version", "1.0"]
    ]
    test_table = Table(test_details, colWidths=[150, 250])
    test_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(test_table)
    elements.append(PageBreak())
    
    # Table of Contents
    elements.append(Paragraph("Table of Contents", styles['Heading1']))
    elements.append(Spacer(1, 10))
    toc_data = [
        ["1. Executive Summary"],
        ["    1.1 Summary"],
        ["    1.2 Approach"],
        ["    1.3 Disclaimer"],
        ["    1.4 Limitations"],
        ["    1.5 OWASP TOP 10"],
        ["    1.6 Vulnerability Scoring"],
        ["2. Checklist"],
        ["3. Scope"],
        ["    3.1 Key Findings"],
        ["    3.2 Vulnerability Graph"],
        ["4. Findings"],
        ["5. Conclusions"],
        ["6. Tools Used"]
    ]
    toc = Table(toc_data)
    toc.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(toc)
    elements.append(PageBreak())
    
    # Executive Summary
    elements.append(Paragraph("1. Executive Summary", styles['Heading1']))
    elements.append(Paragraph("1.1 Summary", styles['Heading2']))
    
    summary_text = f"""
    Our security team conducted a penetration test on {client.name}'s {report.domain_type}
    environment, starting on {report.start_date.strftime('%d %B %Y')}. This assessment, combining automated tools and
    manual checks, aimed to uncover technical weaknesses in the application that
    could be exploited. The report details the identified vulnerabilities, their severity,
    and provides recommendations to mitigate any security risks they might pose.
    
    A total of {stats['total']} vulnerabilities were identified, categorized as follows:
    - Critical: {stats['critical']}
    - High: {stats['high']}
    - Medium: {stats['medium']}
    - Low: {stats['low']}
    """
    elements.append(Paragraph(summary_text, styles['Normal']))
    
    # Approach
    elements.append(Paragraph("1.2 Approach", styles['Heading2']))
    approach_text = """
    • Exploring various application functionalities to enumerate threat &
      vulnerability in alignment with Open Web Application Security Project (OWASP)
      Top 10 vulnerabilities.
    • Performing information gathering/ fingerprinting to identify software used/ its
      version, web server details, ports, and services open, etc.
    • Performing vulnerability scanning to identify common vulnerabilities in the
      application layer and by using Burp and various testing tools in the Kali Linux
      distribution in conjunction with a range of manual analysis. It should be noted
      that customized payloads and attack vectors were configured in Burp Suite to
      further enhance the identification of weakness in the application.
    • Analyzing the automated scan results for any vulnerabilities and ease of
      exploitability and providing proof of concept where safe exploits are possible.
    • Post-Exploitation process will be performed once we get access to the device
      using identified vulnerabilities/exploits.
    • Reporting identified vulnerabilities and recommended solutions to mitigate
      them; for ease of mitigation activities for application support personnel/
      developers' further details of CWEs were added.
    """
    elements.append(Paragraph(approach_text, styles['Normal']))
    elements.append(Spacer(1, 10))
    
    # Disclaimer and other sections omitted for brevity...
    # See the full code in the repository

    # Build the PDF document
    doc.build(elements)
    
    # Get the PDF data and return it
    pdf_data = buffer.getvalue()
    buffer.close()
    return pdf_data

def get_severity_color(severity):
    """Return the appropriate color for each severity level"""
    severity_colors = {
        'Critical': 'danger',
        'High': 'danger',
        'Medium': 'warning',
        'Low': 'info'
    }
    return severity_colors.get(severity, 'secondary')

def image_to_base64(image_data):
    """Convert image binary data to base64 string for HTML embedding"""
    try:
        if image_data:
            encoded = base64.b64encode(image_data).decode('utf-8')
            return f"data:image/jpeg;base64,{encoded}"
    except Exception:
        pass
    return None

def generate_docx_report(report, vulnerabilities, client, stats, images):
    """Generate an editable Word document report"""
    doc = Document()
    
    # Title Page - Following the provided template
    title = doc.add_heading("Vulnerability Assessment", 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    subtitle = doc.add_heading("and Penetration Testing", 0)
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    doc.add_paragraph("")
    doc.add_paragraph("")
    doc.add_paragraph("")
    
    report_title = doc.add_heading(f"{report.domain_type} Security Report", 0)
    report_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    level = doc.add_heading("L1 Report", 1)
    level.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    date = doc.add_heading(f"{datetime.now().strftime('%d %B %Y')}", 1)
    date.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    # Rest of the DOCX generation code omitted for brevity...
    # See the full code in the repository
    
    # Save to memory stream
    docx_buffer = io.BytesIO()
    doc.save(docx_buffer)
    docx_data = docx_buffer.getvalue()
    docx_buffer.close()
    
    return docx_data
```

### app.py
```python
import os
import io
import base64
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

from werkzeug.utils import secure_filename


class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-key-for-testing")

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///vapt.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
db.init_app(app)

with app.app_context():
    from models import ClientInfo, Report, Vulnerability, Image
    db.create_all()

# Template context processor
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

# Custom filter for base64 encoding
@app.template_filter('b64encode')
def b64encode_filter(data):
    if data:
        return base64.b64encode(data).decode('utf-8')
    return None

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/report/new', methods=['GET', 'POST'])
def new_report():
    from models import ClientInfo, Report
    
    if request.method == 'POST':
        # Get form data
        client_name = request.form.get('client_name')
        client_email = request.form.get('client_email')
        client_phone = request.form.get('client_phone')
        client_address = request.form.get('client_address')
        
        # Create or get client
        client = ClientInfo.query.filter_by(name=client_name).first()
        if not client:
            client = ClientInfo(
                name=client_name,
                contact_email=client_email,
                contact_phone=client_phone,
                address=client_address
            )
            db.session.add(client)
            db.session.commit()
        
        # Create report
        report = Report(
            title=request.form.get('title'),
            domain_type=request.form.get('domain_type'),
            start_date=datetime.strptime(request.form.get('start_date'), '%Y-%m-%d'),
            end_date=datetime.strptime(request.form.get('end_date'), '%Y-%m-%d'),
            scope=request.form.get('scope'),
            approach=request.form.get('approach'),
            limitations=request.form.get('limitations'),
            objectives=request.form.get('objectives'),
            client_id=client.id
        )
        db.session.add(report)
        db.session.commit()
        
        flash('Report created successfully!', 'success')
        return redirect(url_for('add_vulnerabilities', report_id=report.id))
    
    return render_template('report_form.html')

@app.route('/report/<int:report_id>/vulnerabilities/add', methods=['GET', 'POST'])
def add_vulnerabilities(report_id):
    from models import Report, Vulnerability
    
    report = Report.query.get_or_404(report_id)
    
    if request.method == 'POST':
        # Get form data
        vulnerability = Vulnerability(
            title=request.form.get('title'),
            description=request.form.get('description'),
            severity=request.form.get('severity'),
            impact=request.form.get('impact'),
            remediation=request.form.get('remediation'),
            report_id=report.id
        )
        db.session.add(vulnerability)
        db.session.commit()
        
        flash('Vulnerability added successfully!', 'success')
        return redirect(url_for('add_vulnerabilities', report_id=report.id))
    
    vulnerabilities = Vulnerability.query.filter_by(report_id=report.id).all()
    return render_template('vulnerability_form.html', report=report, vulnerabilities=vulnerabilities)

@app.route('/report/<int:report_id>/images/add', methods=['GET', 'POST'])
def add_image(report_id):
    from models import Report, Vulnerability, Image
    
    report = Report.query.get_or_404(report_id)
    vulnerabilities = Vulnerability.query.filter_by(report_id=report.id).all()
    
    if request.method == 'POST':
        if 'image' not in request.files:
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        file = request.files['image']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        
        if file:
            # Process image
            image_data = file.read()
            filename = secure_filename(file.filename)
            description = request.form.get('description')
            vulnerability_id = request.form.get('vulnerability_id')
            
            image = Image(
                data=image_data,
                filename=filename,
                description=description,
                report_id=report.id,
                vulnerability_id=vulnerability_id if vulnerability_id else None
            )
            db.session.add(image)
            db.session.commit()
            
            flash('Image added successfully!', 'success')
            return redirect(url_for('add_image', report_id=report.id))
    
    images = Image.query.filter_by(report_id=report.id).all()
    return render_template('image_form.html', report=report, vulnerabilities=vulnerabilities, images=images)

@app.route('/report/<int:report_id>/preview')
def preview_report(report_id):
    from models import Report, Vulnerability, ClientInfo, Image
    from utils import get_severity_color
    
    report = Report.query.get_or_404(report_id)
    vulnerabilities = Vulnerability.query.filter_by(report_id=report.id).all()
    client = ClientInfo.query.get(report.client_id)
    images = Image.query.filter_by(report_id=report.id).all()
    
    # Count vulnerabilities by severity
    stats = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'total': len(vulnerabilities)
    }
    
    for vuln in vulnerabilities:
        severity = vuln.severity.lower()
        if severity in stats:
            stats[severity] += 1
    
    return render_template(
        'report_preview.html', 
        report=report, 
        vulnerabilities=vulnerabilities, 
        client=client,
        stats=stats,
        get_severity_color=get_severity_color,
        images=images
    )

@app.route('/reports')
def list_reports():
    from models import Report, ClientInfo
    
    reports = Report.query.all()
    clients = {client.id: client for client in ClientInfo.query.all()}
    
    return render_template('report_list.html', reports=reports, clients=clients)

@app.route('/report/<int:report_id>/pdf')
def generate_pdf(report_id):
    from models import Report, Vulnerability, ClientInfo, Image
    from utils import generate_report_pdf
    
    report = Report.query.get_or_404(report_id)
    vulnerabilities = Vulnerability.query.filter_by(report_id=report.id).all()
    client = ClientInfo.query.get(report.client_id)
    images = Image.query.filter_by(report_id=report.id).all()
    
    # Count vulnerabilities by severity
    stats = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'total': len(vulnerabilities)
    }
    
    for vuln in vulnerabilities:
        severity = vuln.severity.lower()
        if severity in stats:
            stats[severity] += 1
    
    # Generate PDF
    pdf_data = generate_report_pdf(report, vulnerabilities, client, stats, images)
    
    # Send as downloadable file
    return send_file(
        io.BytesIO(pdf_data),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"{report.title}_vapt_report.pdf"
    )

@app.route('/report/<int:report_id>/docx')
def generate_docx(report_id):
    from models import Report, Vulnerability, ClientInfo, Image
    from utils import generate_docx_report
    
    report = Report.query.get_or_404(report_id)
    vulnerabilities = Vulnerability.query.filter_by(report_id=report.id).all()
    client = ClientInfo.query.get(report.client_id)
    images = Image.query.filter_by(report_id=report.id).all()
    
    # Count vulnerabilities by severity
    stats = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'total': len(vulnerabilities)
    }
    
    for vuln in vulnerabilities:
        severity = vuln.severity.lower()
        if severity in stats:
            stats[severity] += 1
    
    # Generate DOCX
    docx_data = generate_docx_report(report, vulnerabilities, client, stats, images)
    
    # Send as downloadable file
    return send_file(
        io.BytesIO(docx_data),
        mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        as_attachment=True,
        download_name=f"{report.title}_vapt_report.docx"
    )

@app.route('/report/<int:report_id>/delete', methods=['POST'])
def delete_report(report_id):
    from models import Report
    
    report = Report.query.get_or_404(report_id)
    db.session.delete(report)
    db.session.commit()
    
    flash('Report deleted successfully!', 'success')
    return redirect(url_for('list_reports'))

@app.route('/vulnerability/<int:vuln_id>/delete', methods=['POST'])
def delete_vulnerability(vuln_id):
    from models import Vulnerability
    
    vuln = Vulnerability.query.get_or_404(vuln_id)
    report_id = vuln.report_id
    db.session.delete(vuln)
    db.session.commit()
    
    flash('Vulnerability deleted successfully!', 'success')
    return redirect(url_for('add_vulnerabilities', report_id=report_id))
```