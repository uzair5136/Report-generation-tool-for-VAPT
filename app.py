import os
import logging
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
import json
from datetime import datetime
from werkzeug.utils import secure_filename
import io

# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

# Use SQLite database by default
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///vapt_reports.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["UPLOAD_FOLDER"] = "uploads"
db.init_app(app)

with app.app_context():
    # Import models
    from models import Report, Vulnerability, ClientInfo, Image, VulnerabilityGroup
    db.create_all()
    
# Add now function to templates
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# Add base64 encoding filter
@app.template_filter('b64encode')
def b64encode_filter(data):
    if data is None:
        return ''
    return base64.b64encode(data).decode('utf-8')

# Add newline to <br> filter
@app.template_filter('nl2br')
def nl2br_filter(text):
    if text is None:
        return ''
    return text.replace('\n', '<br>')

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/clients')
def list_clients():
    """Display list of all clients"""
    from models import ClientInfo
    
    # Get all clients
    clients = ClientInfo.query.all()
    
    return render_template('client_list.html', clients=clients)

@app.route('/client/new', methods=['GET', 'POST'])
@app.route('/client/<int:client_id>', methods=['GET', 'POST'])
def manage_client(client_id=None):
    """Add or edit a client information record"""
    from models import ClientInfo
    
    # Get existing client or create a new one
    if client_id:
        client = ClientInfo.query.get_or_404(client_id)
    else:
        client = None
        
    # Handle form submission
    if request.method == 'POST':
        # Check if this is a new client or editing existing one
        if client is None:
            client = ClientInfo()
        
        # Update client information from form
        client.name = request.form.get('name')
        client.contact_email = request.form.get('contact_email')
        client.contact_phone = request.form.get('contact_phone')
        client.address = request.form.get('address')
        client.submitted_by = request.form.get('submitted_by')
        client.testing_done_by = request.form.get('testing_done_by')
        client.reviewed_by = request.form.get('reviewed_by')
        
        # Save to database
        db.session.add(client)
        db.session.commit()
        
        flash('Client information saved successfully!', 'success')
        return redirect(url_for('list_clients'))
    
    return render_template('client_form.html', client=client)

@app.route('/report/new', methods=['GET', 'POST'])
def new_report():
    from models import ClientInfo
    
    if request.method == 'POST':
        try:
            # Extract form data
            title = request.form.get('title')
            domain_type = request.form.get('domain_type')
            start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
            end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d')
            scope = request.form.get('scope')
            approach = request.form.get('approach')
            limitations = request.form.get('limitations')
            objectives = request.form.get('objectives')
            
            # Get the selected client
            client_id = request.form.get('client_id')
            
            if not client_id or not client_id.isdigit():
                flash('Please select a valid client.', 'error')
                clients = ClientInfo.query.all()
                return render_template('report_form.html', clients=clients)
                
            client_info = ClientInfo.query.get(int(client_id))
            if not client_info:
                flash('Selected client does not exist.', 'error')
                clients = ClientInfo.query.all()
                return render_template('report_form.html', clients=clients)
            
            # Create new report
            report = Report(
                title=title if title else f"VAPT Report - {client_info.name}",
                domain_type=domain_type,
                start_date=start_date,
                end_date=end_date,
                scope=scope,
                approach=approach,
                limitations=limitations,
                objectives=objectives,
                status="Draft",
                client_id=client_info.id,
                created_at=datetime.now(),
                version=1  # Initialize version
            )
            db.session.add(report)
            db.session.commit()
            
            flash('Report created successfully!', 'success')
            return redirect(url_for('add_vulnerabilities', report_id=report.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating report: {str(e)}', 'danger')
            logging.error(f"Error creating report: {str(e)}")
            return redirect(url_for('new_report'))
    
    # Get all clients for dropdown selection
    clients = ClientInfo.query.all()
    
    # Check if we have any clients, if not redirect to client creation
    if not clients:
        flash('You need to create a client before creating a report.', 'info')
        return redirect(url_for('manage_client'))
        
    return render_template('report_form.html', clients=clients)

@app.route('/report/<int:report_id>/vulnerabilities', methods=['GET', 'POST'])
def add_vulnerabilities(report_id):
    report = Report.query.get_or_404(report_id)
    
    if request.method == 'POST':
        try:
            # Extract vulnerability data
            title = request.form.get('title')
            description = request.form.get('description')
            severity = request.form.get('severity')
            impact = request.form.get('impact')
            remediation = request.form.get('remediation')
            cwe_id = request.form.get('cwe_id')
            group_id = request.form.get('group_id')
            
            # Create new vulnerability
            vulnerability = Vulnerability(
                title=title,
                description=description,
                severity=severity,
                impact=impact,
                remediation=remediation,
                cwe_id=cwe_id,
                report_id=report_id
            )
            
            # Assign to group if specified
            if group_id and group_id.isdigit():
                group = VulnerabilityGroup.query.get(int(group_id))
                if group and group.report_id == report_id:
                    vulnerability.group_id = int(group_id)
            
            db.session.add(vulnerability)
            db.session.commit()
            
            flash('Vulnerability added successfully!', 'success')
            return redirect(url_for('add_vulnerabilities', report_id=report_id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding vulnerability: {str(e)}', 'danger')
            logging.error(f"Error adding vulnerability: {str(e)}")
    
    vulnerabilities = Vulnerability.query.filter_by(report_id=report_id).all()
    vulnerability_groups = VulnerabilityGroup.query.filter_by(report_id=report_id).all()
    return render_template('vulnerability_form.html', report=report, vulnerabilities=vulnerabilities, vulnerability_groups=vulnerability_groups)

@app.route('/report/<int:report_id>/image', methods=['POST'])
def add_image(report_id):
    if 'image' not in request.files:
        return jsonify({"error": "No image provided"}), 400
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({"error": "No image selected"}), 400
    
    try:
        image_data = file.read()
        description = request.form.get('description', '')
        vulnerability_id = request.form.get('vulnerability_id')
        
        image = Image(
            data=image_data,
            filename=secure_filename(file.filename),
            description=description,
            report_id=report_id
        )
        
        if vulnerability_id and vulnerability_id.isdigit():
            image.vulnerability_id = int(vulnerability_id)
        
        db.session.add(image)
        db.session.commit()
        
        return jsonify({"success": True, "id": image.id}), 200
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error adding image: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/report/<int:report_id>/preview')
def preview_report(report_id):
    report = Report.query.get_or_404(report_id)
    vulnerabilities = Vulnerability.query.filter_by(report_id=report_id).all()
    client = ClientInfo.query.get(report.client_id)
    images = Image.query.filter_by(report_id=report_id).all()
    
    # Calculate vulnerability statistics
    critical = sum(1 for v in vulnerabilities if v.severity == 'Critical')
    high = sum(1 for v in vulnerabilities if v.severity == 'High')
    medium = sum(1 for v in vulnerabilities if v.severity == 'Medium')
    low = sum(1 for v in vulnerabilities if v.severity == 'Low')
    
    stats = {
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'total': len(vulnerabilities)
    }
    
    return render_template('report_preview.html', 
                           report=report, 
                           vulnerabilities=vulnerabilities,
                           client=client,
                           stats=stats,
                           images=images)

@app.route('/reports')
def list_reports():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('report_list.html', reports=reports)

@app.route('/report/<int:report_id>/generate-pdf')
def generate_pdf(report_id):
    from utils import generate_report_pdf
    
    report = Report.query.get_or_404(report_id)
    vulnerabilities = Vulnerability.query.filter_by(report_id=report_id).all()
    client = ClientInfo.query.get(report.client_id)
    images = Image.query.filter_by(report_id=report_id).all()
    
    # Calculate vulnerability statistics
    critical = sum(1 for v in vulnerabilities if v.severity == 'Critical')
    high = sum(1 for v in vulnerabilities if v.severity == 'High')
    medium = sum(1 for v in vulnerabilities if v.severity == 'Medium')
    low = sum(1 for v in vulnerabilities if v.severity == 'Low')
    
    stats = {
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'total': len(vulnerabilities)
    }
    
    try:
        logging.info("Starting PDF generation with ReportLab...")
        pdf_data = generate_report_pdf(report, vulnerabilities, client, stats, images)
        logging.info("PDF generation successful!")
        
        # Set the report status to complete
        report.status = "Complete"
        db.session.commit()
        
        # Return the PDF as a downloadable file
        return send_file(
            io.BytesIO(pdf_data),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"VAPT_Report_{report.id}_{datetime.now().strftime('%Y%m%d')}.pdf"
        )
    except Exception as e:
        flash(f'Error generating PDF: {str(e)}', 'danger')
        logging.error(f"Error generating PDF: {str(e)}")
        # For detailed debugging
        import traceback
        logging.error(f"Detailed error traceback: {traceback.format_exc()}")
        return redirect(url_for('preview_report', report_id=report_id))

@app.route('/report/<int:report_id>/generate-docx')
def generate_docx(report_id):
    from utils import generate_docx_report
    
    report = Report.query.get_or_404(report_id)
    vulnerabilities = Vulnerability.query.filter_by(report_id=report_id).all()
    client = ClientInfo.query.get(report.client_id)
    images = Image.query.filter_by(report_id=report_id).all()
    
    # Calculate vulnerability statistics
    critical = sum(1 for v in vulnerabilities if v.severity == 'Critical')
    high = sum(1 for v in vulnerabilities if v.severity == 'High')
    medium = sum(1 for v in vulnerabilities if v.severity == 'Medium')
    low = sum(1 for v in vulnerabilities if v.severity == 'Low')
    
    stats = {
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'total': len(vulnerabilities)
    }
    
    try:
        docx_data = generate_docx_report(report, vulnerabilities, client, stats, images)
        
        # Set the report status to complete
        report.status = "Complete"
        db.session.commit()
        
        # Return the Word document as a downloadable file
        return send_file(
            io.BytesIO(docx_data),
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            as_attachment=True,
            download_name=f"VAPT_Report_{report.id}_{datetime.now().strftime('%Y%m%d')}.docx"
        )
    except Exception as e:
        flash(f'Error generating Word document: {str(e)}', 'danger')
        logging.error(f"Error generating Word document: {str(e)}")
        return redirect(url_for('preview_report', report_id=report_id))

@app.route('/report/<int:report_id>/delete', methods=['POST'])
def delete_report(report_id):
    try:
        report = Report.query.get_or_404(report_id)
        
        # Delete associated vulnerabilities
        Vulnerability.query.filter_by(report_id=report_id).delete()
        
        # Delete associated images
        Image.query.filter_by(report_id=report_id).delete()
        
        # Delete the report
        db.session.delete(report)
        db.session.commit()
        
        flash('Report deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting report: {str(e)}', 'danger')
        logging.error(f"Error deleting report: {str(e)}")
    
    return redirect(url_for('list_reports'))

@app.route('/vulnerability/<int:vuln_id>/delete', methods=['POST'])
def delete_vulnerability(vuln_id):
    try:
        vuln = Vulnerability.query.get_or_404(vuln_id)
        report_id = vuln.report_id
        
        # Delete the vulnerability
        db.session.delete(vuln)
        db.session.commit()
        
        flash('Vulnerability deleted successfully!', 'success')
        return redirect(url_for('add_vulnerabilities', report_id=report_id))
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting vulnerability: {str(e)}', 'danger')
        logging.error(f"Error deleting vulnerability: {str(e)}")
        return redirect(url_for('list_reports'))

@app.route('/report/<int:report_id>/groups', methods=['GET', 'POST'])
def manage_vulnerability_groups(report_id):
    """Create and manage vulnerability groups for a report"""
    report = Report.query.get_or_404(report_id)
    groups = VulnerabilityGroup.query.filter_by(report_id=report_id).all()
    
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            description = request.form.get('description', '')
            
            group = VulnerabilityGroup(
                name=name,
                description=description,
                report_id=report_id
            )
            db.session.add(group)
            db.session.commit()
            
            flash('Vulnerability group created successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating vulnerability group: {str(e)}', 'danger')
            logging.error(f"Error creating vulnerability group: {str(e)}")
    
    return render_template('vulnerability_groups.html', report=report, groups=groups)

@app.route('/group/<int:group_id>/delete', methods=['POST'])
def delete_vulnerability_group(group_id):
    """Delete a vulnerability group"""
    try:
        group = VulnerabilityGroup.query.get_or_404(group_id)
        report_id = group.report_id
        
        # Remove group association from vulnerabilities
        for vuln in group.vulnerabilities:
            vuln.group_id = None
        
        # Delete the group
        db.session.delete(group)
        db.session.commit()
        
        flash('Vulnerability group deleted successfully!', 'success')
        return redirect(url_for('manage_vulnerability_groups', report_id=report_id))
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting vulnerability group: {str(e)}', 'danger')
        logging.error(f"Error deleting vulnerability group: {str(e)}")
        return redirect(url_for('list_reports'))

@app.route('/client/<int:client_id>/delete', methods=['POST'])
def delete_client(client_id):
    """Delete a client and all associated reports"""
    try:
        client = ClientInfo.query.get_or_404(client_id)
        
        # Get all reports associated with this client
        reports = Report.query.filter_by(client_id=client_id).all()
        
        # Delete all resources for each report
        for report in reports:
            # Delete vulnerability groups
            VulnerabilityGroup.query.filter_by(report_id=report.id).delete()
            
            # Delete vulnerabilities
            Vulnerability.query.filter_by(report_id=report.id).delete()
            
            # Delete images
            Image.query.filter_by(report_id=report.id).delete()
            
            # Delete the report
            db.session.delete(report)
        
        # Delete the client
        db.session.delete(client)
        db.session.commit()
        
        flash('Client and all associated reports deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting client: {str(e)}', 'danger')
        logging.error(f"Error deleting client: {str(e)}")
    
    return redirect(url_for('list_clients'))

@app.route('/vulnerability/<int:vuln_id>/assign-group', methods=['POST'])
def assign_vulnerability_to_group(vuln_id):
    """Assign a vulnerability to a group"""
    try:
        vuln = Vulnerability.query.get_or_404(vuln_id)
        group_id = request.form.get('group_id')
        
        if group_id and group_id.isdigit():
            # Check if group exists and belongs to the same report
            group = VulnerabilityGroup.query.get(int(group_id))
            if group and group.report_id == vuln.report_id:
                vuln.group_id = int(group_id)
            else:
                vuln.group_id = None
        else:
            vuln.group_id = None
            
        db.session.commit()
        
        flash('Vulnerability assigned to group successfully!', 'success')
        return redirect(url_for('add_vulnerabilities', report_id=vuln.report_id))
    except Exception as e:
        db.session.rollback()
        flash(f'Error assigning vulnerability to group: {str(e)}', 'danger')
        logging.error(f"Error assigning vulnerability to group: {str(e)}")
        return redirect(url_for('list_reports'))

@app.route('/report/<int:report_id>/checklist', methods=['GET', 'POST'])
def manage_checklist(report_id):
    """Manage security testing checklist for a report"""
    report = Report.query.get_or_404(report_id)
    client = ClientInfo.query.get(report.client_id)
    
    if request.method == 'POST':
        try:
            # Get checklist data from form submission
            checklist_data = request.form.get('checklist_data')
            if checklist_data:
                # Store checklist data in the report
                report.checklist_data = checklist_data
                db.session.commit()
                flash('Security checklist saved successfully.', 'success')
            else:
                flash('No checklist data received.', 'warning')
        except Exception as e:
            db.session.rollback()
            flash(f'Error saving checklist: {str(e)}', 'danger')
            logging.error(f"Error saving checklist: {str(e)}")
    
    return render_template('checklist_form.html', report=report, client=client)
