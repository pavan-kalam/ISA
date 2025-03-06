# API Research Documentation

## Overview

This document provides an overview of the OSINT (Open Source Intelligence) APIs integrated into our web application. The selected APIs are:

1. [VirusTotal API](#virustotal-api)
2. [AbuseIPDB API](#abuseipdb-api)
3. [Shodan API](#shodan-api)
4. [Have I Been Pwned (HIBP) API](#have-i-been-pwned-hibp-api)

Each section includes details on authentication, request methods, and example usage.

---

## 1. VirusTotal API

- **Description:** VirusTotal is a service that analyzes files and URLs for viruses, worms, trojans, and other types of malicious content. It aggregates results from multiple antivirus engines and website scanners.

- **Authentication:** Requires an API key for access, and for this users must create an account to obtain the key.

- **Request Methods:**
  - **GET:** To retrieve analysis reports for URLs.
  - **POST:** To submit URLs for analysis.

## 2. AbuseIPDB API

- **Description:** AbuseIPDB is a tool that allows users to report and check IP addresses that are suspected of malicious activity. It provides a way to identify potentially harmful IPs based on user reports.

- **Authentication:** Requires an API key for access, and for this users must create an account to obtain the key.

- **Request Methods:**
  - **GET:** To retrieve information about specific IP addresses.
  - **POST:** To report an IP address as abusive.

## 3. Shodan API

- **Description:** Shodan is a search engine for Internet-connected devices. It allows users to find specific types of devices and services exposed to the internet, providing valuable insights into potential vulnerabilities.

- **Authentication:** Requires an API key for access, and for this users must create an account to obtain the key.

- **Request Methods:**
  - **GET:** To search for devices and retrieve information about them.

## 4. Have I Been Pwned (HIBP) API

- **Description:** HIBP is a service that allows users to check if their email addresses or phone numbers have been compromised in data breaches. It provides a simple way to assess the security of personal information.

- **Authentication:** Not required for public endpoints.

- **Request Methods:**
  - **GET:** To check if an email address has been compromised.