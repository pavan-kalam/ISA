# ShopSmart Solutions - E-Commerce Platform

## Project Overview
*ShopSmart Solutions* is a secure and user-friendly e-commerce platform designed to provide a seamless online shopping experience. The project integrates *OSINT tools*, *Large Language Models (LLMs)*, and aligns with the *NIST Cybersecurity Framework (CSF) 2.0* and *NIST Risk Management Framework (RMF)* to ensure robust cybersecurity and risk management.

---

## Key Features
1. **Real-Time Threat Intelligence**:
   - Integrates free OSINT tools like *VirusTotal*, *Have I Been Pwned (HIBP)*, *AbuseIPDB*, *PhishTank*, *Shodan*, *OWASP ZAP*, and *Snort* for threat monitoring.

2. **Risk Management**:
   - Aligns with NIST CSF 2.0 and RMF to identify, assess, and mitigate risks.

3. **Automated Risk Scoring**:
   - Uses *OpenAI GPT-4* for automating risk scoring and generating actionable insights.

4. **Secure E-Commerce Platform**:
   - Protects customer data, prevents fraud, and ensures a safe shopping experience.

---

## Technology Stack
| **Component**      | **Technology**                                                                 |
|---------------------|-------------------------------------------------------------------------------|
| **Front-End**       | React.js                                                                      |
| **Back-End**        | Python (Flask)                                                         |
| **Database**        | PostgreSQL                                                                    |
| **OSINT Tools**     | VirusTotal, HIBP, AbuseIPDB, PhishTank, Shodan, OWASP ZAP, Snort              |
| **LLM Model**       | OpenAI GPT-4                                                                  |

---

## OSINT Tools Integration

1. **VirusTotal**: Scans files and URLs for malware and phishing threats.
2. **Have I Been Pwned (HIBP)**: Checks for compromised credentials.
3. **AbuseIPDB**: Identifies and blocks malicious IP addresses.
4. **PhishTank**: Detects and blocks phishing websites.
5. **Shodan**: Monitors the platform’s infrastructure for vulnerabilities.
6. **OWASP ZAP**: Detects and prevents SQL injection and other web application vulnerabilities.
7. **Snort**: Detects and prevents DDoS attacks and other network-based threats.

---

## Repository Structure

/real-time-threat-intelligance/
│── /docs/           # Documentation
│── /src/            # Source code
│── /api/            # OSINT API integrations
│── /db/             # Database 
│── README.md        # Project overview
│── .gitignore       # Ignore unnecessary files


## Project Document Reference

**Team Structure**:         [/docs/team_structure.md]
**Technology Stack**:       [/docs/tech_stack.md]
**NIST Framework Summary**: [/docs/nist_framework_summary.md]
**OSINT Research Report**:  [/docs/osint_research.md]