#!/usr/bin/env python3
"""
CLI for Kavach.AI backend operations:
- scan (static analyzers)
- classify (ML on .bytes)
- analyze-logs (runtime trace analysis)
- run-analysis (docker sandbox run)
- history / get-report
"""
from pathlib import Path
import json
import os
import subprocess
import sys
import time
import shutil
import typer
import requests

from byteconvert import file_to_bytes
from report_generator import generate_report
from scripts.malware_classifier import classify_bytes_file
from scripts.sys_log_analysis import process_log_file
from scripts.static1 import StaticAnalyzer as BasicAnalyzer
from scripts.static2 import StaticAnalyzer as EnhancedAnalyzer
from scripts.static3 import StaticAnalyzer as AdvancedAnalyzer
from scripts.static4 import StaticAnalyzer as CompleteAnalyzer

app = typer.Typer()
BASE = Path(__file__).resolve().parent
SAMPLE_DIR = BASE / "samples"
OUTPUT_DIR = BASE / "output"
SCAN_HISTORY_DIR = BASE / "scan_history"
STORED_REPORTS = BASE / "stored_reports"
for d in (SAMPLE_DIR, OUTPUT_DIR, SCAN_HISTORY_DIR, STORED_REPORTS):
    d.mkdir(parents=True, exist_ok=True)

ANALYZERS = {
    "basic": BasicAnalyzer,
    "enhanced": EnhancedAnalyzer,
    "advanced": AdvancedAnalyzer,
    "complete": CompleteAnalyzer
}

def _store_scan_history(entry: dict):
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    scan_id = f"scan_{timestamp}"
    history_entry = {"scan_id": scan_id, "timestamp": timestamp, "data": entry}
    out = SCAN_HISTORY_DIR / f"{scan_id}.json"
    out.write_text(json.dumps(history_entry, indent=2))
    return str(out)

@app.command()
def scan(
    file: Path = typer.Option(..., exists=True, help="Path to file to scan"),
    scan_type: str = typer.Option("basic", help="basic|enhanced|advanced|complete"),
    vt_api_key: str = typer.Option(None, help="Optional VirusTotal API key"),
    save_report: bool = typer.Option(False, help="Save PDF report to stored_reports")
):
    """Run static analysis (and .bytes analysis)"""
    typer.echo()
    typer.secho(f"🔍 Running {scan_type} analysis", fg=typer.colors.BLUE, bold=True)
    typer.secho("-" * 70, fg=typer.colors.CYAN)
    typer.echo(f"File: {file}")
    if scan_type not in ANALYZERS:
        typer.secho(f"Error: Invalid scan_type '{scan_type}'", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    analyzer_cls = ANALYZERS[scan_type]
    # Convert file to bytes
    bytes_path = Path("temp_bytes") / (file.stem + ".bytes")
    bytes_path.parent.mkdir(exist_ok=True, parents=True)
    ok = file_to_bytes(str(file), str(bytes_path))
    if not ok:
        typer.secho("Error: Byte conversion failed", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # Run analyzers
    analyzer = analyzer_cls(vt_api_key) if "vt_api_key" in analyzer_cls.__init__.__code__.co_varnames else analyzer_cls()
    result_orig = analyzer.analyze_file(str(file))
    try:
        result_bytes = analyzer.analyze_file(str(bytes_path))
    except Exception:
        result_bytes = {"error": "bytes analysis failed"}

    combined = {
        "file": str(file.name),
        "original": result_orig,
        "bytes": result_bytes,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    # Save report if requested
    report_path = None
    if save_report:
        fname = f"security_report_{int(time.time())}.pdf"
        report_path = STORED_REPORTS / fname

        # Report generator expects each scan entry to be a dict of analysis sections.
        report_sections = {
            "original": result_orig if isinstance(result_orig, dict) else {"error": "original analysis unavailable"},
            "bytes": result_bytes if isinstance(result_bytes, dict) else {"error": "bytes analysis unavailable"},
        }

        if isinstance(result_orig, dict) and "malwareClassification" in result_orig:
            report_sections["malwareClassification"] = result_orig["malwareClassification"]

        generate_report({"files": {file.name: report_sections}}, str(report_path))
        combined["report_path"] = str(report_path)

    history_file = _store_scan_history(combined)
    typer.echo()
    typer.secho("✓ Analysis complete!", fg=typer.colors.GREEN, bold=True)
    typer.secho("-" * 70, fg=typer.colors.CYAN)
    typer.echo(f"History file: {history_file}")
    if report_path:
        typer.secho(f"Report saved:  {report_path}", fg=typer.colors.YELLOW)
    typer.echo()

@app.command()
def classify(
    file: Path = typer.Option(..., exists=True, help="Path to file or .bytes to classify"),
    model: Path = typer.Option("saved_w.model", help="Path to XGBoost model file"),
    threshold: float = typer.Option(0.5, help="Normal threshold")
):
    """Classify a file using byte-frequency XGBoost model"""
    # If not .bytes, convert
    if file.suffix.lower() != ".bytes":
        bytes_path = Path("temp_bytes") / (file.stem + ".bytes")
        bytes_path.parent.mkdir(exist_ok=True, parents=True)
        ok = file_to_bytes(str(file), str(bytes_path))
        if not ok:
            typer.secho("Error: Byte conversion failed", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
    else:
        bytes_path = file

    typer.echo()
    typer.secho(f"🤖 Classifying with XGBoost model", fg=typer.colors.BLUE, bold=True)
    typer.secho("-" * 70, fg=typer.colors.CYAN)
    typer.echo(f"File: {bytes_path}")
    typer.echo(f"Model: {model}")
    typer.echo(f"Threshold: {threshold}")
    
    res = classify_bytes_file(str(bytes_path), model_path=str(model), normal_threshold=threshold)
    
    if 'error' in res:
        typer.secho(f"Error: {res['error']}", fg=typer.colors.RED, bold=True)
    else:
        typer.echo()
        typer.secho("=" * 70, fg=typer.colors.CYAN)
        typer.secho(" Malware Classification Result ".center(70, "*"), fg=typer.colors.CYAN, bold=True)
        typer.secho("=" * 70, fg=typer.colors.CYAN)
        typer.echo(f"File: {bytes_path}")
        typer.secho("-" * 70, fg=typer.colors.CYAN)
        
        predicted = res['predicted_malware']
        confidence = res['max_probability']
        
        if "Normal" in predicted:
            typer.secho(f"Predicted: {predicted}", fg=typer.colors.GREEN, bold=True)
            typer.secho("Confidence: Low (below threshold, likely normal)", fg=typer.colors.GREEN)
        else:
            typer.secho(f"Predicted: {predicted}", fg=typer.colors.RED, bold=True)
            typer.secho(f"Confidence: {confidence:.4f}", fg=typer.colors.YELLOW, bold=True)
        
        typer.secho("-" * 70, fg=typer.colors.CYAN)
        typer.echo("Class Probabilities:")
        typer.secho("-" * 70, fg=typer.colors.CYAN)
        
        for malware_name, prob in res['probabilities'].items():
            prob_str = f"{prob:.4f}" if prob > 0 else "N/A "
            typer.echo(f"{malware_name:<70} | {prob_str}")
        
        typer.secho("=" * 70, fg=typer.colors.CYAN)
        typer.echo()

@app.command()
def analyze_logs(logfile: Path = typer.Option(..., exists=True, help="Trace/log file to analyze")):
    """Analyze a trace/log file for behavioral indicators"""
    typer.echo()
    typer.secho(f"📊 Log Analysis Report", fg=typer.colors.BLUE, bold=True)
    typer.secho("-" * 80, fg=typer.colors.CYAN)
    typer.echo(f"File: {logfile}")
    
    res = process_log_file(str(logfile))
    
    if not isinstance(res, dict):
        typer.echo(json.dumps(res, indent=2))
        return
    
    # Summary section
    typer.echo()
    typer.secho("📈 Summary", fg=typer.colors.BLUE, bold=True)
    typer.secho("-" * 80, fg=typer.colors.CYAN)
    typer.echo(f"Total Lines Analyzed:      {res.get('total_lines', 'N/A')}")
    typer.echo(f"Flagged Events (%):        {res.get('flagged_percentage', 'N/A')}%")
    typer.echo(f"Overall Confidence Score:  {res.get('confidence', 'N/A')}")
    
    # Suspicion verdict
    is_suspicious = res.get('is_suspicious', False)
    high_confidence = res.get('high_confidence', False)
    
    typer.echo()
    if is_suspicious and high_confidence:
        typer.secho("⚠️  VERDICT: SUSPICIOUS (High Confidence)", fg=typer.colors.RED, bold=True)
    elif is_suspicious:
        typer.secho("⚠️  VERDICT: SUSPICIOUS (Low Confidence)", fg=typer.colors.YELLOW, bold=True)
    else:
        typer.secho("✓ VERDICT: LIKELY BENIGN", fg=typer.colors.GREEN, bold=True)
    
    # Flag summary
    flag_summary = res.get('flag_summary', {})
    if flag_summary:
        typer.echo()
        typer.secho("🚩 Detected Flags", fg=typer.colors.BLUE, bold=True)
        typer.secho("-" * 80, fg=typer.colors.CYAN)
        for flag_type, count in sorted(flag_summary.items(), key=lambda x: x[1], reverse=True):
            typer.echo(f"  {flag_type:<30} {count:>3} occurrences")
    
    # Suspicious flags (non-benign)
    flags = res.get('flags', [])
    suspicious_flags = [f for f in flags if not f.get('is_common_benign', False)]
    
    if suspicious_flags:
        typer.echo()
        typer.secho("🔴 High Priority Flags (Non-Benign)", fg=typer.colors.RED, bold=True)
        typer.secho("-" * 80, fg=typer.colors.CYAN)
        for flag in suspicious_flags[:10]:  # Show first 10
            typer.secho(f"  • {flag.get('rule', 'unknown').upper()}", fg=typer.colors.YELLOW, bold=True)
            typer.echo(f"    Description: {flag.get('description', 'N/A')}")
            typer.echo(f"    Details: {flag.get('details', 'N/A')[:70]}...")
            typer.echo(f"    Line: {flag.get('line', 'N/A')} | Weight: {flag.get('weight', 'N/A')}")
            typer.echo()
        
        if len(suspicious_flags) > 10:
            typer.secho(f"  ... and {len(suspicious_flags) - 10} more suspicious flags", fg=typer.colors.YELLOW)
    
    # Benign flags summary
    benign_flags = [f for f in flags if f.get('is_common_benign', False)]
    if benign_flags:
        typer.echo()
        typer.secho(f"ℹ️  Common Benign Flags", fg=typer.colors.CYAN, bold=True)
        typer.secho("-" * 80, fg=typer.colors.CYAN)
        typer.echo(f"Found {len(benign_flags)} common benign events (typically safe):")
        benign_summary = {}
        for f in benign_flags:
            rule = f.get('rule', 'unknown')
            benign_summary[rule] = benign_summary.get(rule, 0) + 1
        for rule_type, count in sorted(benign_summary.items(), key=lambda x: x[1], reverse=True):
            typer.echo(f"  • {rule_type}: {count} occurrences")
    
    # Recommendations
    recommendations = res.get('recommendations', [])
    if recommendations:
        typer.echo()
        typer.secho("💡 Recommendations", fg=typer.colors.BLUE, bold=True)
        typer.secho("-" * 80, fg=typer.colors.CYAN)
        for rec in recommendations:
            typer.echo(f"  • {rec}")
    
    # Thresholds
    thresholds = res.get('thresholds', {})
    if thresholds:
        typer.echo()
        typer.secho("⚙️  Detection Thresholds", fg=typer.colors.CYAN)
        typer.secho("-" * 80, fg=typer.colors.CYAN)
        for key, val in thresholds.items():
            typer.echo(f"  {key:<20} {val}")
    
    typer.echo()

@app.command()
def run_analysis(
    filename: str = typer.Option(..., help="Name of sample (in samples/) to run in docker sandbox"),
    use_api: bool = typer.Option(False, "--use-api", help="Use Flask API route instead")
):
    """Run Docker sandbox analysis (requires docker) or call the Flask API route."""
    # Extract just the filename (in case user passes path like "samples/file.exe")
    filename = Path(filename).name
    sample = SAMPLE_DIR / filename
    if not sample.exists():
        typer.secho(f"Error: Sample {sample} not found in {SAMPLE_DIR}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    typer.echo()
    typer.secho(f"🔬 Malware Analysis - Docker Sandbox", fg=typer.colors.BLUE, bold=True)
    typer.secho("-" * 70, fg=typer.colors.CYAN)
    typer.echo(f"Sample: {sample}")

    if use_api:
        app_script = BASE / "app.py"
        if not app_script.exists():
            typer.secho("Error: Flask API script app.py not found", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)

        typer.secho("🚀 Starting Flask API server...", fg=typer.colors.BLUE)
        app_process = subprocess.Popen(
            [sys.executable, str(app_script)],
            cwd=str(BASE),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        try:
            url = "http://127.0.0.1:5000/api/run-analysis"
            for attempt in range(20):
                if app_process.poll() is not None:
                    out, err = app_process.communicate(timeout=1)
                    typer.secho(f"Error: Flask app exited early:\n{out}\n{err}", fg=typer.colors.RED, err=True)
                    raise typer.Exit(code=1)
                try:
                    resp = requests.post(url, json={"filename": filename}, timeout=30)
                    resp.raise_for_status()
                    typer.echo()
                    typer.secho("✓ Analysis Result", fg=typer.colors.GREEN, bold=True)
                    typer.secho("-" * 70, fg=typer.colors.CYAN)
                    typer.echo(json.dumps(resp.json(), indent=2))
                    typer.echo()
                    return
                except requests.RequestException:
                    time.sleep(1)
            typer.secho("Error: Flask server failed to start or respond", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        finally:
            if app_process.poll() is None:
                app_process.terminate()
                time.sleep(2)
                if app_process.poll() is None:
                    app_process.kill()

    # Check Docker daemon is available
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True)
    except subprocess.CalledProcessError:
        typer.secho("Error: Docker daemon not running", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    # Build image if missing
    check_img = subprocess.run(
        ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}", "malware-analysis:1.1"],
        capture_output=True,
        text=True,
    )
    if "malware-analysis:1.1" not in check_img.stdout:
        typer.secho("📦 Building malware-analysis image...", fg=typer.colors.YELLOW, bold=True)
        subprocess.run(["docker", "build", "-t", "malware-analysis:1.1", "."], check=True)
        typer.secho("✓ Image built successfully", fg=typer.colors.GREEN)

    docker_cmd = [
        "docker", "run", "--rm", "--name", "malware-analysis",
        "--security-opt", "no-new-privileges=true",
        "--cap-drop=ALL", "--cap-add=SYS_PTRACE",
        "--memory=512m", "--memory-swap=512m",
        "--cpus=1", "--pids-limit=100",
        "--ulimit", "nofile=1024:1024", "--ulimit", "nproc=100:100",
        "--network=none", "--read-only",
        "--tmpfs", "/tmp:size=100m,mode=1777",
        "--tmpfs", "/home/analyst/.wine:size=500m,mode=0700,uid=1000,gid=1000",
        "-v", f"{SAMPLE_DIR.absolute()}:/home/analyst/samples:ro",
        "-v", f"{OUTPUT_DIR.absolute()}:/home/analyst/output:rw",
        "malware-analysis:1.1",
        # Sandbox script will be executed inside container, passing just the filename (not path)
        "bash", "-c", f'/usr/local/bin/auto_analyze.sh {filename}'
    ]

    typer.echo()
    typer.secho("🐳 Executing docker sandbox...", fg=typer.colors.BLUE, bold=True)
    typer.secho("-" * 70, fg=typer.colors.CYAN)
    p = subprocess.Popen(docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
    for line in iter(p.stdout.readline, ''):
        typer.secho(f"  {line.rstrip()}", fg=typer.colors.WHITE)
    p.wait()
    typer.secho("-" * 70, fg=typer.colors.CYAN)
    if p.returncode != 0:
        typer.secho("✗ Docker run failed", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)
    typer.secho("✓ Docker analysis finished", fg=typer.colors.GREEN, bold=True)

    trace_path = OUTPUT_DIR / "trace.log"
    if not trace_path.exists():
        typer.secho("⚠ Warning: No trace.log generated in output/", fg=typer.colors.YELLOW)
    else:
        typer.secho(f"📄 Trace log: {trace_path}", fg=typer.colors.GREEN)
    typer.echo()

@app.command()
def history(limit: int = 20):
    """List recent scan history entries"""
    files = sorted(SCAN_HISTORY_DIR.glob("scan_*.json"), key=os.path.getmtime, reverse=True)[:limit]
    if not files:
        typer.secho("No scan history found", fg=typer.colors.YELLOW)
        return
    typer.echo()
    typer.secho("📋 Scan History", fg=typer.colors.BLUE, bold=True)
    typer.secho("-" * 110, fg=typer.colors.CYAN)
    typer.secho(f"{'Scan ID':<25} {'Timestamp':<25} {'File':<60}", bold=True)
    typer.secho("-" * 110, fg=typer.colors.CYAN)
    for f in files:
        data = json.loads(f.read_text())
        scan_id = data.get('scan_id', '')
        timestamp = data.get('timestamp', '')
        filename = data.get('data', {}).get('file', '')
        typer.echo(f"{scan_id:<25} {timestamp:<25} {filename:<60}")
    typer.secho("-" * 110, fg=typer.colors.CYAN)
    typer.echo()

@app.command()
def get_report(filename: str):
    """Print path to stored report if present"""
    p = STORED_REPORTS / filename
    if not p.exists():
        typer.secho(f"Error: Report not found: {filename}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.echo()
    typer.secho("📄 Report Found", fg=typer.colors.GREEN, bold=True)
    typer.secho("-" * 70, fg=typer.colors.CYAN)
    typer.echo(f"Path: {p}")
    typer.echo()

if __name__ == "__main__":
    app()