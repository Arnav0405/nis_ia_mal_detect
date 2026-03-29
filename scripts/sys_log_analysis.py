import json
import re
from typing import List, Dict, Tuple
import os
from groq import Groq
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
import logging
from retry import retry

# Update logging configuration to use local path
log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'log_analysis.log')

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(log_file)
    ]
)
logger = logging.getLogger(__name__)  # Fix logger name

# Groq API configuration
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "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")
GROQ_MODEL = "llama-3.2-1b-preview"

# Define chunk size (LLaMA-3.1-8B has a ~8000 token context window)
CHUNK_SIZE = 1000  # Lines per chunk
MAX_PROMPT_CHARS = 6000  # Increased but safe limit for API

@dataclass
class DetectionRule:
    name: str
    pattern: str
    weight: float  # Severity score (0-1)
    description: str
    is_common_benign: bool = False  # Flag for patterns often seen in benign software

# Define detection rules with weights and context
DETECTION_RULES = [
    DetectionRule(
        name="suspicious_execve",
        pattern=r"execve\(\"(/usr/bin/wine-preloader|/usr/bin/unknown|/bin/sh)\"",
        weight=0.8,
        description="Execution of unexpected or sensitive binaries",
    ),
    DetectionRule(
        name="unauthorized_file_access",
        pattern=r"open\(\"(/etc/passwd|/etc/shadow|/root/.*?\.secret)\"",
        weight=0.9,
        description="Access to sensitive system files",
    ),
    DetectionRule(
        name="missing_dll",
        pattern=r"stat\(\"(.*?\.dll)\"\,.*ENOENT",
        weight=0.4,
        description="Attempt to load missing DLLs, common in malware but also installers",
        is_common_benign=True,
    ),
    DetectionRule(
        name="invalid_readlink",
        pattern=r"readlink\(\"(.*?)\"\,.*EINVAL",
        weight=0.1,
        description="Invalid readlink calls, often benign in Wine but can indicate probing",
        is_common_benign=True,
    ),
    DetectionRule(
        name="suspicious_mmap",
        pattern=r"mmap\(.*PROT_EXEC.*MAP_PRIVATE",
        weight=0.6,
        description="Memory mapping with executable permissions",
    ),
    DetectionRule(
        name="network_activity",
        pattern=r"socket\(|connect\(|bind\(",
        weight=0.7,
        description="Network-related system calls, potentially malicious if unexpected",
    ),
    DetectionRule(
        name="persistence_attempt",
        pattern=r"open\(\"(/etc/cron\.|/.bashrc|/.zshrc)\"\,.*O_WRONLY",
        weight=0.95,
        description="Attempts to modify system persistence mechanisms",
    ),
]

# Percentage threshold for considering a file suspicious
SUSPICIOUS_PERCENTAGE_THRESHOLD = 5.0  # 5% of lines flagged
HIGH_CONFIDENCE_THRESHOLD = 10.0  # 10% for high confidence

def check_file_exists(file_path: str) -> bool:
    """Check if a file exists and is readable."""
    file_path = Path(file_path)
    if file_path.exists() and file_path.is_file():  # Fixed: Properly call is_file() as a method
        logger.info(f"File found: {file_path}")
        return True
    logger.error(f"File not found or inaccessible: {file_path}")
    return False

def list_directory(path: str) -> List[str]:
    """List files in a directory for debugging."""
    try:
        return [str(p) for p in Path(path).glob("/*") if p.is_file()]
    except Exception as e:
        logger.error(f"Error listing directory {path}: {e}")
        return []

def read_log_file(file_path: str) -> List[str]:
    """Read the log file and return lines."""
    if not check_file_exists(file_path):
        return []
    encodings = ['utf-8', 'latin-1', 'ascii']
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                lines = f.readlines()
            logger.info(f"Read {len(lines)} lines from {file_path} with {encoding} encoding")
            return lines
        except UnicodeDecodeError:
            logger.warning(f"Failed to read {file_path} with {encoding} encoding")
        except Exception as e:
            logger.error(f"Error reading log file {file_path}: {e}")
            return []
    logger.error(f"Could not read {file_path} with any encoding")
    return []

def chunk_logs(lines: List[str], chunk_size: int) -> List[List[str]]:
    """Split log lines into chunks."""
    chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]
    logger.info(f"Split into {len(chunks)} chunks")
    return chunks

def analyze_chunk(chunk: List[str], rules: List[DetectionRule]) -> List[Dict]:
    """Analyze a chunk of logs for suspicious patterns using heuristics."""
    flags = []
    chunk_text = ''.join(chunk)

    for rule in rules:
        matches = re.finditer(rule.pattern, chunk_text, re.IGNORECASE)
        for match in matches:
            line_num = chunk_text[:match.start()].count('\n') + 1
            flags.append({
                "rule": rule.name,
                "weight": rule.weight,
                "details": match.group(0)[:200],  # Limit detail length
                "line": line_num,
                "description": rule.description,
                "is_common_benign": rule.is_common_benign
            })

    return flags

@retry(tries=3, delay=1, backoff=2)
def call_grok_api(chunk: List[str], rules: List[DetectionRule]) -> List[Dict]:
    """
    Call Groq API with LLaMA-3.1-8B-Instant for chunk analysis.
    Falls back to heuristic analysis if the API call fails.
    """
    client = Groq(api_key=GROQ_API_KEY)
    chunk_text = ''.join(chunk)[:MAX_PROMPT_CHARS]  # Limit to avoid token overflow

    prompt = (
        "You are a security analyst examining system call trace logs from a sandboxed environment. "
        "Analyze the following logs for suspicious behavior, such as unauthorized file access, "
        "suspicious executions, missing DLL loads, memory mapping with executable permissions, "
        "network activity, or persistence attempts. Consider that some patterns (e.g., missing DLLs, "
        "readlink errors) may occur in benign software like installers running in Wine. "
        "Return a JSON list of detected issues, each with 'rule' (e.g., 'suspicious_execve'), "
        "'description' (brief explanation), 'line' (line number), and 'details' (log excerpt). "
        "Only flag behaviors that are likely malicious or highly unusual.\n\n"
        f"Logs (line numbers start at 1):\n{chunk_text}"
    )

    try:
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are a precise security analyst. Respond only in JSON format."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            max_tokens=1000,
            temperature=0.5
        )
        try:
            result = json.loads(response.choices[0].message.content)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON from Groq API: {e}")
            return analyze_chunk(chunk, rules)

        flags = result.get("flags", [])
        if not isinstance(flags, list):
            logger.error("Groq API returned invalid flags format")
            return analyze_chunk(chunk, rules)

        # Validate and normalize response
        normalized_flags = []
        for flag in flags:
            rule = flag.get("rule", "unknown")
            line = flag.get("line", 1)
            if not isinstance(line, int) or line < 1 or line > len(chunk):
                line = 1
            rule_info = next((r for r in rules if r.name == rule), None)
            normalized_flags.append({
                "rule": rule,
                "weight": rule_info.weight if rule_info else 0.5,
                "details": str(flag.get("details", ""))[:200],
                "line": line,
                "description": flag.get("description", "Unknown issue"),
                "is_common_benign": rule_info.is_common_benign if rule_info else False
            })

        logger.info(f"Groq API returned {len(normalized_flags)} flags")
        return normalized_flags

    except Exception as e:
        logger.error(f"Error calling Groq API: {e}")
        logger.info("Falling back to heuristic analysis")
        return analyze_chunk(chunk, rules)

def calculate_confidence(flags: List[Dict], total_lines: int) -> Tuple[float, Dict]:
    """
    Calculate confidence score based on weighted flags and percentage of lines flagged.
    """
    weighted_score = 0.0
    flag_counts = defaultdict(int)
    flagged_lines = set()
    has_benign = False

    for flag in flags:
        weighted_score += flag["weight"]
        flag_counts[flag["rule"]] += 1
        flagged_lines.add(flag["line"])
        if flag["is_common_benign"]:
            has_benign = True

    # Calculate percentage of lines flagged
    flagged_percentage = (len(flagged_lines) / total_lines * 100) if total_lines > 0 else 0

    # Adjust score for benign patterns once
    if has_benign:
        weighted_score *= 0.8

    # Normalize score to 0-100
    confidence = min(weighted_score * 10, 100.0) * (flagged_percentage / 100)

    return confidence, flag_counts

def process_log_file(file_path: str) -> Dict:
    """Process the log file and generate a detailed analysis report."""
    # Read log file
    lines = read_log_file(file_path)
    if not lines:
        return {"error": "Failed to read log file", "confidence": 0.0, "suspicious": False}

    total_lines = len(lines)
    chunks = chunk_logs(lines, CHUNK_SIZE)
    all_flags = []

    # Process each chunk
    for i, chunk in enumerate(chunks, 1):
        logger.info(f"Processing chunk {i}/{len(chunks)} ({len(chunk)} lines)")
        flags = call_grok_api(chunk, DETECTION_RULES)
        all_flags.extend([f | {"chunk": i} for f in flags])
        logger.info(f"Chunk {i} flags: {len(flags)}")

    # Calculate confidence and flag statistics
    confidence, flag_counts = calculate_confidence(all_flags, total_lines)
    flagged_percentage = (len({f["line"] for f in all_flags}) / total_lines * 100) if total_lines > 0 else 0

    # Determine suspiciousness
    is_suspicious = flagged_percentage >= SUSPICIOUS_PERCENTAGE_THRESHOLD
    high_confidence = flagged_percentage >= HIGH_CONFIDENCE_THRESHOLD

    # Contextual analysis for false positive reduction
    suspicious_combinations = 0
    for flag in all_flags:
        if flag["rule"] == "missing_dll":
            nearby_flags = [f for f in all_flags if abs(f["line"] - flag["line"]) < 50]
            if any(f["rule"] in ["suspicious_mmap", "suspicious_execve"] for f in nearby_flags):
                suspicious_combinations += 1

    # Adjust confidence based on combinations
    confidence += suspicious_combinations * 5.0
    confidence = min(confidence, 100.0)

    # Generate recommendations
    recommendations = []
    if is_suspicious:
        recommendations.append("Isolate the file and conduct deeper analysis.")
        if high_confidence:
            recommendations.append("High confidence of malicious behavior; consider blocking execution.")
        if flag_counts.get("unauthorized_file_access", 0) > 0:
            recommendations.append("Check for credential harvesting or privilege escalation attempts.")
        if flag_counts.get("missing_dll", 0) > 10:
            recommendations.append("Verify DLL dependencies; potential DLL hijacking.")
    else:
        recommendations.append("Monitor for additional suspicious activity, but no immediate action required.")

    # Prepare result
    result = {
        "file": str(Path(file_path).name),
        "total_lines": total_lines,
        "flagged_percentage": round(flagged_percentage, 2),
        "confidence": round(confidence, 2),
        "is_suspicious": is_suspicious,
        "high_confidence": high_confidence,
        "flag_summary": dict(flag_counts),
        "flags": all_flags,
        "thresholds": {
            "suspicious": SUSPICIOUS_PERCENTAGE_THRESHOLD,
            "high_confidence": HIGH_CONFIDENCE_THRESHOLD
        },
        "recommendations": recommendations
    }

    return result

def generate_report(result: Dict) -> str:
    """Generate a formatted report for analysts."""
    report = [
        f"Log Analysis Report: {result.get('file', 'Unknown')}",
        "=" * 50,
        f"Total Lines: {result.get('total_lines', 0)}",
        f"Flagged Percentage: {result.get('flagged_percentage', 0)}%",
        f"Confidence Score: {result.get('confidence', 0)}/100",
        f"Suspicious: {result.get('is_suspicious', False)}",
        f"High Confidence: {result.get('high_confidence', False)}",
        f"Thresholds: Suspicious >= {result.get('thresholds', {}).get('suspicious', 0)}%, "
        f"High Confidence >= {result.get('thresholds', {}).get('high_confidence', 0)}%",
        "\nFlag Summary:"
    ]

    for rule, count in result.get("flag_summary", {}).items():
        rule_info = next((r for r in DETECTION_RULES if r.name == rule), None)
        desc = rule_info.description if rule_info else "Unknown"
        report.append(f"  {rule}: {count} ({desc})")

    report.append("\nRecommendations:")
    for rec in result.get("recommendations", []):
        report.append(f"  - {rec}")

    report.append("\nDetailed Flags:")
    for flag in result.get("flags", [])[:10]:
        report.append(
            f"  Chunk {flag['chunk']}, Line {flag['line']}: {flag['rule']} "
            f"(Weight: {flag['weight']}) - {flag['description']}\n"
            f"    Details: {flag['details']}"
        )
    if len(result.get("flags", [])) > 10:
        report.append(f"  ... {len(result.get('flags', [])) - 10} more flags omitted")

    return "\n".join(report)

def main():
    # Debug available files
    logger.info("Listing files in /kaggle/input/test-virus:")
    available_files = list_directory("/kaggle/input/test-virus")
    for f in available_files:
        logger.info(f"Found: {f}")

    log_files = [
        "/kaggle/input/test-virus/trace.log",
        "/kaggle/input/test-virus/normal_trace.log"
    ]
    for log_file in log_files:
        logger.info(f"Analyzing {log_file}")
        result = process_log_file(log_file)
        report = generate_report(result)
        print(report)
        print("\n" + "=" * 50 + "\n")

if __name__ == "__main__":
    try:
        # Install groq package if not present (Kaggle-specific)
        # os.system("pip install groq retry")
        main()
    except Exception as e:
        logger.error(f"Script failed: {e}")
        print(f"Error: Script failed with {e}. Check logs in /kaggle/working/log_analysis.log")