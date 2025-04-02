from app import db
from datetime import datetime

class ClientInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contact_email = db.Column(db.String(100))
    contact_phone = db.Column(db.String(20))
    address = db.Column(db.Text)
    
    # Document revision information
    submitted_by = db.Column(db.String(100))
    
    # Test performed details
    testing_done_by = db.Column(db.String(100))
    reviewed_by = db.Column(db.String(100))
    
    # Relationship
    reports = db.relationship('Report', backref='client', lazy=True)
    
    def __repr__(self):
        return f'<Client {self.name}>'

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
    version = db.Column(db.Integer, default=1)  # Track report versions
    checklist_data = db.Column(db.Text)  # JSON string of checklist items and their status
    
    # Foreign Keys
    client_id = db.Column(db.Integer, db.ForeignKey('client_info.id'), nullable=False)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='report', lazy=True, cascade='all, delete-orphan')
    images = db.relationship('Image', backref='report', lazy=True, cascade='all, delete-orphan')
    vulnerability_groups = db.relationship('VulnerabilityGroup', backref='report', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Report {self.title}>'

class VulnerabilityGroup(db.Model):
    """Group related vulnerabilities together for better organization"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign Keys
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='group', lazy=True)
    
    def __repr__(self):
        return f'<VulnerabilityGroup {self.name}>'

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # Critical, High, Medium, Low
    impact = db.Column(db.Text)
    remediation = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    cwe_id = db.Column(db.String(20))  # Common Weakness Enumeration ID
    
    # Foreign Keys
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('vulnerability_group.id'), nullable=True)
    
    # Relationships
    images = db.relationship('Image', backref='vulnerability', lazy=True)
    
    def __repr__(self):
        return f'<Vulnerability {self.title}>'

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.LargeBinary, nullable=False)  # Store image as binary data
    filename = db.Column(db.String(255))
    description = db.Column(db.Text)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Foreign Keys
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerability.id'), nullable=True)
    
    def __repr__(self):
        return f'<Image {self.filename}>'
