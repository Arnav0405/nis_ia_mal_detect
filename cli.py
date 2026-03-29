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
import time
import shutil
import typer

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
SAMPLE_DIR = BASE.parent / "samples"
OUTPUT_DIR = BASE.parent / "output"
SCAN_HISTORY_DIR = BASE.parent / "scan_history"
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
    typer.echo(f"Running {scan_type} analysis on {file}")
    if scan_type not in ANALYZERS:
        raise typer.Exit(code=1, message="Invalid scan_type")

    analyzer_cls = ANALYZERS[scan_type]
    # Convert file to bytes
    bytes_path = Path("temp_bytes") / (file.stem + ".bytes")
    bytes_path.parent.mkdir(exist_ok=True, parents=True)
    ok = file_to_bytes(str(file), str(bytes_path))
    if not ok:
        raise typer.Exit(code=1, message="Byte conversion failed")

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
    typer.echo(f"Analysis complete. History stored at: {history_file}")
    if report_path:
        typer.echo(f"Report saved: {report_path}")
    else:
        typer.echo(json.dumps(combined, indent=2))

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
            raise typer.Exit(code=1, message="Byte conversion failed")
    else:
        bytes_path = file

    typer.echo(f"Classifying {bytes_path} with model {model}")
    res = classify_bytes_file(str(bytes_path), model_path=str(model), normal_threshold=threshold)
    typer.echo(json.dumps(res, indent=2))

@app.command()
def analyze_logs(logfile: Path = typer.Option(..., exists=True, help="Trace/log file to analyze")):
    """Analyze a trace/log file for behavioral indicators"""
    typer.echo(f"Analyzing log: {logfile}")
    res = process_log_file(str(logfile))
    typer.echo(json.dumps(res, indent=2))

@app.command()
def run_analysis(filename: str = typer.Option(..., help="Name of sample (in samples/) to run in docker sandbox")):
    """Run Docker sandbox analysis (requires docker)"""
    sample = SAMPLE_DIR / filename
    if not sample.exists():
        raise typer.Exit(code=1, message=f"Sample {sample} not found in {SAMPLE_DIR}")
    docker_cmd = [
        "docker", "run", "--rm", "--name", "malware-analysis",
        "--security-opt", "no-new-privileges=true",
        "--cap-drop=ALL", "--cap-add=SYS_PTRACE",
        "--memory=512m", "--memory-swap=512m",
        "--cpus=1", "--pids-limit=100",
        "--ulimit", "nofile=1024:1024", "--ulimit", "nproc=100:100",
        "--network=none", "--read-only",
        "--tmpfs", "/tmp:size=100m,mode=1777",
        "-v", f"{SAMPLE_DIR.absolute()}:/home/analyst/samples:ro",
        "-v", f"{OUTPUT_DIR.absolute()}:/home/analyst/output:rw",
        "malware-analysis:1.1",
        "bash", "-c", f'echo "{filename}" | /usr/local/bin/auto_analyze.sh'
    ]
    typer.echo("Executing docker (may take a while)...")
    proc = subprocess.run(docker_cmd, capture_output=True, text=True)
    typer.echo(proc.stdout)
    if proc.returncode != 0:
        typer.echo(proc.stderr, err=True)
        raise typer.Exit(code=1, message="Docker run failed")
    typer.echo("Docker analysis finished")

@app.command()
def history(limit: int = 20):
    """List recent scan history entries"""
    files = sorted(SCAN_HISTORY_DIR.glob("scan_*.json"), key=os.path.getmtime, reverse=True)[:limit]
    for f in files:
        data = json.loads(f.read_text())
        print(f"{f.name} - {data.get('timestamp')} - {data.get('data', {}).get('file', '')}")

@app.command()
def get_report(filename: str):
    """Print path to stored report if present"""
    p = STORED_REPORTS / filename
    if not p.exists():
        raise typer.Exit(code=1, message="Report not found")
    typer.echo(str(p))

if __name__ == "__main__":
    app()