# api/models.py
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

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