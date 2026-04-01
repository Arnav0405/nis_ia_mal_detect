# Making Malware Detection System

## Project Overview

This repository contains a malware analysis platform with both a CLI (`cli.py`) and an API server (`app.py`).

The project supports:
- static file scanning with multiple analyzer modes
- XGBoost-based byte-frequency classification
- log/trace analysis
- sandbox execution of Windows samples inside Docker via Wine
- report generation and stored scan history
- API endpoints for file upload, scan, classification, sandbox execution, and reporting

## Repository Layout

- `cli.py` — command-line interface for scan, classify, analyze_logs, run_analysis, history, and get_report
- `app.py` — Flask REST API server
- `Dockerfile` — builds the sandbox image `malware-analysis:1.1`
- `auto_analyze.sh` — sandbox execution script inside the Docker image
- `byteconvert.py` — converts binaries into `.bytes` format
- `report_generator.py` — PDF report generation helpers
- `scripts/` — static analyzers and malware classification/log analysis logic
- `samples/` — example executable samples
- `output/` — sandbox output files and generated trace/log artifacts
- `scan_history/` — saved scan history JSON entries
- `stored_reports/` — generated PDF reports
- `saved_w.model` — XGBoost model file for classification

## Setup

1. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. If using the API server, create a `.env` file with:

   ```bash
   GROQ_API_KEY=your_groq_key_here
   VT_API_KEY=your_virustotal_key_here
   ```

   `.env` should remain local and not be committed.

4. Ensure Docker is installed and the daemon is running for sandbox execution.

## CLI Usage

### Basic commands

```bash
python cli.py --help
python cli.py scan --file samples/11.exe --scan-type basic
python cli.py scan --file samples/11.exe --scan-type complete --save-report
python cli.py classify --file samples/11.exe --model saved_w.model
python cli.py analyze-logs --logfile output/trace.log
python cli.py run-analysis --filename 11.exe
python cli.py run-analysis --filename 11.exe --use-api
python cli.py history
python cli.py get-report <filename>
```

### Notes on CLI behavior

- `scan` runs a static analyzer and also converts the target to `.bytes` for secondary analysis.
- `--save-report` stores a PDF file in `stored_reports/`.
- Scan history entries are saved under `scan_history/`.
- The Docker sandbox will build `malware-analysis:1.1` automatically if it is not present.
- `--use-api` starts `app.py` and calls the API endpoint for sandbox execution.

## API Server

Start the Flask API server with:

```bash
python app.py
```

Available endpoints:

- `POST /api/scan/<scan_type>` — upload a file and run the selected analyzer (`basic`, `enhanced`, `advanced`, `complete`)
- `POST /api/classify-malware` — upload a file, convert it to `.bytes`, and classify it
- `POST /api/analyze-logs` — analyze an existing trace log file in `output/`
- `POST /api/upload-sample` — upload a sample file into `samples/`
- `POST /api/run-analysis` — execute the Docker sandbox for a sample
- `GET /api/reports/<filename>` — download a saved report PDF
- `POST /api/download-report` — generate and download a PDF from analysis JSON data
- `POST /api/download-log-report` — generate and download a log analysis PDF and store it in `stored_reports/`
- `GET /api/scan-history` — retrieve saved scan history entries
- `POST /api/chat` — send a chat request through the Groq API

## Docker Sandbox

The sandbox image is built from `Dockerfile`:

```bash
docker build -t malware-analysis:1.1 .
```

The image installs:
- `bash`, `wine`, `strace`, `file`, `coreutils`, `grep`
- `python3`, `py3-pip`
- `binwalk`

The sandbox runs `auto_analyze.sh`, which:
- checks that the requested .exe exists in `samples/`
- initializes a Wine prefix under `/home/analyst/.wine`
- runs the EXE with Wine
- traces execution with `strace`
- formats trace output into `output/trace.log`
- extracts strings and performs basic static file checks

## Important Notes

- `app.py` requires `GROQ_API_KEY` for the `/api/chat` endpoint.
- `cli.py` imports `requests` only for `--use-api` mode.
- `auto_analyze.sh` writes logs to `output/analysis.log` and other sandbox artifacts to `output/`.
- Required directories are created automatically by the CLI and API server.

## Troubleshooting

- If `cli.py` fails due to missing packages, install them with `pip install <package>`.
- If `run-analysis` fails, verify Docker is running and the sandbox image exists or can be built.
- If the API route fails, check that `app.py` starts successfully and `.env` contains valid keys.

## Project Status

This project now includes:
- CLI-based static and byte-level analysis
- XGBoost classification support
- log analysis reporting
- Docker sandbox execution for Windows samples
- Flask API endpoints for analysis workflows and report downloads
- persistent scan history and report storage
