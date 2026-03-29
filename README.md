# Making Malware Detection System

## Steps

2. **Create a Virtual Environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Test The Following Commands**:

   ```bash
   python3 cli.py --help
   python3 cli.py scan --file samples/11.exe --scan-type basic
   python3 cli.py scan --file samples/11.exe --scan-type complete --save-report
   python3 cli.py classify --file samples/11.exe --model saved_w.model
   python3 cli.py analyze-logs --logfile output/trace.log
   python3 cli.py run-analysis --filename 11.exe
   python3 cli.py history
   python3 cli.py get-report --help

   ```

## Scan Status

- `scan` is working from CLI.
- `--save-report` is also working and stores PDF reports in `stored_reports/`.
- Scan history is written to `scan_history/`.

### Common Scan Commands

```bash
# Basic scan
python3 cli.py scan --file samples/11.exe --scan-type basic

# Full scan + PDF report
python3 cli.py scan --file samples/11.exe --scan-type complete --save-report

# Check recent history
python3 cli.py history
```

## Things to Work On

1. Setup API Keys

### API Key Setup (Safe)

1. Create a local `.env` from `.env.example`.
2. Set your keys in `.env`:

```bash
GROQ_API_KEY=your_groq_key_here
VT_API_KEY=your_virustotal_key_here
```

Notes:
- `.env` is gitignored and should never be committed.
- The app now reads keys from environment variables only.

#### In the cli.py

2. Expand test coverage for scan/classify/log analysis
3. Create an XGBoost Model using the microsoft virus dataset then setup the `classify` route
4. Run a docker container to run the `run-analysis` route. Edit and solve the issues.
