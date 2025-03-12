# API Research

## Overview
This document provides an overview of the OSINT APIs integrated into the application.

## Integrated OSINT APIs

- **ZoomEye**: A search engine for Internet-connected devices, allowing users to find and analyze devices connected to the internet.
- **IntelX**: A comprehensive intelligence platform that provides data on email breaches and other cyber threats.
- **URLScan**: A service that analyzes URLs for potential security risks and provides detailed reports.

## API Endpoints
The application utilizes the following endpoints to interact with the OSINT services:
- `/api/osint`: Fetches data from all integrated OSINT services.
- `/api/breach`: Checks for email breaches using IntelX.
- `/api/zoomeye`: Searches for devices using ZoomEye.
- `/api/urlscan`: Analyzes URLs using URLScan.

## API Keys
Ensure that the following API keys are configured in the `config.json` file:
- `ZOOMEYE_API_KEY`
- `INTELX_API_KEY`
- `URLSCAN_API_KEY`
