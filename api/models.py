# api/models.py
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    def __repr__(self):
        return f'<User {self.username}>'

class TvaMapping(db.Model):
    __tablename__ = 'tva_mapping'
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.now())
    threat_name = db.Column(db.String(100), nullable=False)
    likelihood = db.Column(db.Integer, default=1)
    impact = db.Column(db.Integer, default=1)
    def __repr__(self):
        return f'<TvaMapping {self.threat_name}>'

class ThreatData(db.Model):
    __tablename__ = 'threat_data'
    id = db.Column(db.Integer, primary_key=True)
    threat_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.now())
    def __repr__(self):
        return f'<ThreatData {self.threat_type}>'

class AlertLog(db.Model):
    __tablename__ = 'alert_logs'
    id = db.Column(db.Integer, primary_key=True)
    threat = db.Column(db.String(255), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)
    threat_type = db.Column(db.String(50), nullable=False, default="Other")
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.now())
    def __repr__(self):
        return f'<AlertLog {self.threat}>'

class IncidentLog(db.Model):
    __tablename__ = 'incident_logs'
    id = db.Column(db.Integer, primary_key=True)
    threat_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    response_plan = db.Column(db.Text, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=db.func.now())
    def __repr__(self):
        return f'<IncidentLog {self.description}>'

class Asset(db.Model):
    __tablename__ = 'assets'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    type = Column(String(50), nullable=False)
    identifier = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)