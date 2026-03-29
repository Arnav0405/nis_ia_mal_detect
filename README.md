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

   ```python
   python cli.py --help
   python cli.py scan --file <<samples/sample.exe>> --scan-type complete --save-report
   python cli.py classify --file <<samples/sample.exe>> --model saved_w.model
   python cli.py analyze-logs --logfile <<output/trace.log>>
   python cli.py run-analysis --filename <<sample.exe>>
   python cli.py history

   ```

## Things to Work On

1. Setup API Keys

#### In the cli.py

2. `scan` route doesn't work
3. Create an XGBoost Model using the microsoft virus dataset then setup the `classify` route
4. Run a docker container to run the `run-analysis` route. Edit and solve the issues.
