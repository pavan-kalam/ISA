# risk_generator.py
import os
import csv
from fpdf import FPDF
from datetime import datetime
from api.models import db, ThreatData, IncidentLog, AlertLog
from custom_logging import setup_logger
logger = setup_logger('risk_generator')

class ThreatReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_pdf(self, filename="threat_report.pdf"):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        pdf.cell(200, 10, txt="Threat Intelligence Report", ln=True, align="C")
        pdf.cell(200, 10, txt=f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        
        pdf.ln(10)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "Threats", ln=True)
        pdf.set_font("Arial", size=12)
        threats = ThreatData.query.all()
        for threat in threats[:10]:
            pdf.multi_cell(0, 10, f"Type: {threat.threat_type}\nDesc: {threat.description}\nRisk: {threat.risk_score}\nDate: {threat.created_at}")
            pdf.ln(5)
        
        output_path = os.path.join(self.output_dir, filename)
        try:
            pdf.output(output_path)
            logger.info(f"PDF report generated at: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to generate PDF: {str(e)}")
            raise

    def generate_csv(self, filename="threat_report.csv"):
        output_path = os.path.join(self.output_dir, filename)
        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = ['type', 'description', 'risk_score', 'created_at', 'category']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            threats = ThreatData.query.all()
            incidents = IncidentLog.query.all()
            alerts = AlertLog.query.all()
            
            for threat in threats:
                writer.writerow({
                    'type': threat.threat_type,
                    'description': threat.description,
                    'risk_score': threat.risk_score,
                    'created_at': threat.created_at,
                    'category': 'Threat'
                })
            for incident in incidents:
                writer.writerow({
                    'type': incident.threat_type,
                    'description': incident.description,
                    'risk_score': incident.risk_score,
                    'created_at': incident.created_at,
                    'category': 'Incident'
                })
            for alert in alerts:
                writer.writerow({
                    'type': alert.threat_type,
                    'description': alert.threat,
                    'risk_score': alert.risk_score,
                    'created_at': alert.created_at,
                    'category': 'Alert'
                })
        
        logger.info(f"CSV report generated at: {output_path}")
        return output_path

# Integration in app.py
if __name__ == "__main__":
    from app import app, db
    with app.app_context():
        generator = ThreatReportGenerator()
        generator.generate_pdf()
        generator.generate_csv()