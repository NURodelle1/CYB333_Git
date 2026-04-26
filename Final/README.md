IOC ENRICHMENT AUTOMATION

This repository contains a Python script that automates enrichment of Indicators of Compromise (IOCs) using public threat intelligence APIs. The goal is to reduce manual SOC analysis and produce clean output files that can be reviewed or attached to tickets.

WHAT THIS TOOL DOES

Accepts IP addresses and file hashes as input.
Enriches IOCs using VirusTotal, AlienVault OTX, and AbuseIPDB.
Generates a CSV results file.
Optionally generates a plain text executive summary.
Continues execution even if one data source fails.

REQUIREMENTS

Python version 3.9 or newer.

Python dependency:
requests

Install dependency by running:
pip install requests

API KEYS

The following API keys are required and must be set as environment variables. Keys must not be hardcoded in the script.

VT_API_KEY
OTX_API_KEY
ABUSEIPDB_API_KEY

SETTING API KEYS ON WINDOWS

Open PowerShell and run:

setx VT_API_KEY "your_virustotal_key"
setx OTX_API_KEY "your_otx_key"
setx ABUSEIPDB_API_KEY "your_abuseipdb_key"

After running these commands, close and reopen the terminal.

INPUT FILE

Create a text file with one IOC per line. Blank lines are ignored.

Example iocs.txt:

8.8.8.8
203.128.0.33
44d88612fea8a8f36de82e1278abb02f

RUNNING THE SCRIPT

Interactive mode is recommended.

Run:
python IOC_Enrichment_Final.py

A menu will appear with the following options:

1 CSV only
2 CSV and Executive Summary
3 Executive Summary only

After selecting an option, you will be prompted to provide the path to the IOC input file. The script confirms when output files are created.

COMMAND LINE MODE

CSV only:
python IOC_Enrichment_Final.py --file iocs.txt --mode csv

Executive summary only:
python IOC_Enrichment_Final.py --file iocs.txt --mode exec

CSV and executive summary:
python IOC_Enrichment_Final.py --file iocs.txt --mode both

Optional arguments:

--csv results.csv
--summary executive_summary.txt
--sleep 1.0
--quiet

OUTPUT FILES

CSV RESULTS

The CSV includes IOC value and type, VirusTotal detections and reputation data, OTX pulse counts, AbuseIPDB confidence data, calculated risk score and level, recommended action, and evidence strength. Results are sorted with highest risk listed first.

EXECUTIVE SUMMARY

The executive summary is a plain text file that includes total IOCs processed, high, medium, and low risk counts, top IOCs by risk score, and recommended actions.

NOTES AND LIMITATIONS

AbuseIPDB supports IP addresses only.
API rate limits depend on your key tier.
The script includes basic retry logic for temporary API errors.

USE OF AI

AI tools were used to assist with CSV reporting, executive summary output, and usability improvements. All code was manually reviewed and tested.

AUTHOR

Rodelle Suguitan
CYB333 Final Project
