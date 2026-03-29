from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from scripts.static1 import StaticAnalyzer as BasicAnalyzer
from scripts.static2 import StaticAnalyzer as EnhancedAnalyzer 
from scripts.static3 import StaticAnalyzer as AdvancedAnalyzer
from scripts.static4 import StaticAnalyzer as CompleteAnalyzer
from byteconvert import file_to_bytes
import os
from report_generator import generate_report, generate_log_report
import tempfile
import time
from groq import Groq
from datetime import datetime
from scripts.malware_classifier import classify_bytes_file
import numpy as np
from scripts.sys_log_analysis import process_log_file
import subprocess
import shutil
import json

# Increase timeout and enable debug logging
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

UPLOAD_FOLDER = 'temp_uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize Groq client with specific API key
groq_client = Groq(api_key="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")

# Create required directories
REQUIRED_DIRS = ['temp_uploads', 'temp_bytes', 'temp_reports', 'stored_reports']
for dir_name in REQUIRED_DIRS:
    os.makedirs(dir_name, exist_ok=True)

# Add new config for sample and output directories
SAMPLE_DIR = os.path.join(os.path.dirname(__file__), '..', 'samples')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'output')

# Ensure directories exist
os.makedirs(SAMPLE_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Add new directory for scan history
SCAN_HISTORY_DIR = os.path.join(os.path.dirname(__file__), '..', 'scan_history')
os.makedirs(SCAN_HISTORY_DIR, exist_ok=True)

def process_file(file_obj, analyzer_class):
    """Process file with byte conversion and analysis"""
    if not file_obj:
        return {'error': 'No file provided'}, 400

    try:
        # Save original file
        orig_path = os.path.join('temp_uploads', file_obj.filename)
        file_obj.save(orig_path)

        # Convert to bytes format
        bytes_path = os.path.join('temp_bytes', f"{os.path.splitext(file_obj.filename)[0]}.bytes")
        byte_conversion_success = file_to_bytes(orig_path, bytes_path)

        if not byte_conversion_success:
            return {'error': 'Failed to convert file to bytes format'}, 500

        # Analyze original file
        analyzer = analyzer_class()
        results = analyzer.analyze_file(orig_path)

        # Add byte analysis results if conversion was successful
        if os.path.exists(bytes_path):
            try:
                bytes_results = analyzer.analyze_file(bytes_path)
                results['bytes_analysis'] = {
                    'file_type': bytes_results.get('file_type', 'Unknown'),
                    'size': bytes_results.get('file_size', 0),
                    'hashes': bytes_results.get('hashes', {}),
                    'analysis': bytes_results.get('analysis', {})
                }
            except Exception as e:
                results['bytes_analysis'] = {'error': f'Byte analysis failed: {str(e)}'}
        
        # Store report with both analyses
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f'security_report_{timestamp}.pdf'
        report_path = store_report({
            'original_analysis': results,
            'bytes_analysis': results.get('bytes_analysis', {}),
            'timestamp': timestamp,
            'filename': file_obj.filename
        }, report_filename)

        results['report_file'] = report_filename
        return results

    except Exception as e:
        return {'error': str(e)}, 500
    finally:
        # Cleanup temporary files
        for path in [orig_path, bytes_path]:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except:
                    pass

def store_report(report_data, filename):
    """Store report permanently"""
    stored_path = os.path.join('stored_reports', filename)
    generate_report(report_data, stored_path)
    return stored_path

def store_scan_history(scan_data, report_path):
    """Store scan results and report in history"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    scan_id = f"scan_{timestamp}"
    
    history_entry = {
        'scan_id': scan_id,
        'timestamp': timestamp,
        'data': scan_data,
        'report_path': report_path
    }
    
    # Save to JSON file
    history_file = os.path.join(SCAN_HISTORY_DIR, f"{scan_id}.json")
    with open(history_file, 'w') as f:
        json.dump(history_entry, f, indent=2)
    
    return scan_id

@app.route('/api/reports/<filename>', methods=['GET'])
def get_stored_report(filename):
    """Retrieve stored report"""
    try:
        report_path = os.path.join('stored_reports', filename)
        if os.path.exists(report_path):
            return send_file(
                report_path,
                mimetype='application/pdf',
                as_attachment=True,
                download_name=filename
            )
        return jsonify({'error': 'Report not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/<scan_type>', methods=['POST'])
def scan_file(scan_type):
    """Unified scan endpoint with byte analysis"""
    analyzers = {
        'basic': BasicAnalyzer,
        'enhanced': EnhancedAnalyzer,
        'advanced': AdvancedAnalyzer,
        'complete': CompleteAnalyzer
    }
    
    if scan_type not in analyzers:
        return jsonify({'error': 'Invalid scan type'}), 400
        
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file provided'}), 400
        
    try:
        results = process_file(file, analyzers[scan_type])
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download-report', methods=['POST'])
def download_report():
    data = request.json
    if not data:
        return jsonify({'error': 'No analysis data provided'}), 400

    try:
        # Create temp directory for reports if it doesn't exist
        os.makedirs('temp_reports', exist_ok=True)

        # Generate unique filename
        timestamp = int(time.time())
        filename = f'security_analysis_report_{timestamp}.pdf'
        pdf_path = os.path.join('temp_reports', filename)

        # Generate report
        generate_report(data, pdf_path)

        # Send file
        response = send_file(
            pdf_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )

        # Clean up after sending
        @response.call_on_close
        def cleanup():
            try:
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)
            except Exception as e:
                print(f"Cleanup error: {e}")

        return response

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        data = request.json
        messages = data.get('messages', [])
        system_prompt = data.get('systemPrompt', '')

        # Prepare messages for Groq
        formatted_messages = [
            {"role": "system", "content": system_prompt}
        ] + messages

        # Get completion from Groq using Mixtral model with optimized parameters
        chat_completion = groq_client.chat.completions.create(
            model="qwen-2.5-coder-32b",
            messages=formatted_messages,
            temperature=0.7,
            max_tokens=2048,
            top_p=0.9,
            stop=None,
            stream=False
        )

        # Extract and format response
        response = chat_completion.choices[0].message.content

        # Add response to chat history
        return jsonify({
            "response": response,
            "status": "success"
        })

    except Exception as e:
        print(f"Chat error: {str(e)}")  # For debugging
        return jsonify({
            "error": "Failed to generate response",
            "details": str(e)
        }), 500

@app.route('/api/classify-malware', methods=['POST'])
def classify_malware():
    """Endpoint for malware classification using .bytes file."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    try:
        # Save the uploaded file temporarily
        temp_path = os.path.join('temp_uploads', file.filename)
        file.save(temp_path)

        # Convert to .bytes format
        bytes_path = os.path.join('temp_bytes', f"{os.path.splitext(file.filename)[0]}.bytes")
        if not file_to_bytes(temp_path, bytes_path):
            return jsonify({'error': 'Failed to convert file to .bytes format'}), 500

        # Classify the .bytes file
        classification_results = classify_bytes_file(bytes_path)
        
        # Convert numpy float32 to Python float
        if 'max_probability' in classification_results:
            classification_results['max_probability'] = float(classification_results['max_probability'])
        
        if 'probabilities' in classification_results:
            classification_results['probabilities'] = {
                k: float(v) for k, v in classification_results['probabilities'].items()
            }

        return jsonify(classification_results)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        # Cleanup temporary files
        for path in [temp_path, bytes_path]:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except:
                    pass

@app.route('/api/analyze-logs', methods=['POST'])
def analyze_logs():
    """Analyze generated trace.log file"""
    try:
        data = request.json
        filename = data.get('filename', 'trace.log')
        
        # Get path to trace.log
        log_path = os.path.join(OUTPUT_DIR, filename)
        if not os.path.exists(log_path):
            return jsonify({'error': 'Log file not found'}), 404

        # Process the log file
        results = process_log_file(log_path)
        if not results:
            return jsonify({'error': 'Failed to process log file'}), 500

        return jsonify(results)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload-sample', methods=['POST'])
def upload_sample():
    """Handle file upload to samples directory"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    try:
        # Save file to samples directory
        filepath = os.path.join(SAMPLE_DIR, file.filename)
        file.save(filepath)
        return jsonify({'message': 'File uploaded successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/run-analysis', methods=['POST'])
def run_analysis():
    """Execute Docker analysis command"""
    try:
        data = request.json
        filename = data.get('filename')
        if not filename:
            return jsonify({'error': 'Filename not provided'}), 400

        # First try to remove any existing container with the same name
        try:
            subprocess.run(['docker', 'rm', '-f', 'malware-analysis'], 
                         capture_output=True, 
                         check=False)  # Don't raise error if container doesn't exist
        except Exception as e:
            print(f"Warning: Failed to remove existing container: {e}")

        # Create named pipe for input
        print(f"Starting analysis for {filename}")
        
        # Docker command without -it flags
        docker_cmd = [
            'docker', 'run',
            '--rm',  # Remove container after execution
            '--name', 'malware-analysis',
            '--security-opt', 'no-new-privileges=true',
            '--cap-drop=ALL',
            '--cap-add=SYS_PTRACE',
            '--memory=512m',
            '--memory-swap=512m',
            '--cpus=1',
            '--pids-limit=100',
            '--ulimit', 'nofile=1024:1024',
            '--ulimit', 'nproc=100:100',
            '--network=none',
            '--read-only',
            '--tmpfs', '/tmp:size=100m,mode=1777',
            '--tmpfs', '/home/analyst/.wine:size=500m,mode=0700,uid=1000,gid=1000',
            '-v', f'{os.path.abspath(SAMPLE_DIR)}:/home/analyst/samples:ro',
            '-v', f'{os.path.abspath(OUTPUT_DIR)}:/home/analyst/output:rw',
            'malware-analysis:1.1',
            'bash', '-c', f'echo "{filename}" | /usr/local/bin/auto_analyze.sh'
        ]

        # Execute Docker command
        print("Executing Docker command:", ' '.join(docker_cmd))
        process = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            check=False  # Don't raise error on non-zero exit
        )

        print("Docker stdout:", process.stdout)
        print("Docker stderr:", process.stderr)

        if process.returncode != 0:
            return jsonify({
                'error': 'Docker analysis failed',
                'details': process.stderr,
                'stdout': process.stdout
            }), 500

        # Check if trace.log was generated
        trace_log_path = os.path.join(OUTPUT_DIR, 'trace.log')
        if not os.path.exists(trace_log_path):
            return jsonify({
                'error': 'Trace log not generated',
                'details': 'Analysis completed but no trace log was produced'
            }), 500

        return jsonify({
            'message': 'Analysis completed successfully',
            'details': process.stdout
        })

    except Exception as e:
        print(f"Analysis error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/download-log-report', methods=['POST'])
def download_log_report():
    """Generate and download log analysis report"""
    data = request.json
    if not data:
        return jsonify({'error': 'No analysis data provided'}), 400

    try:
        # Create temp directory for reports if it doesn't exist
        os.makedirs('temp_reports', exist_ok=True)

        # Generate unique filename
        timestamp = int(time.time())
        filename = f'log_analysis_report_{timestamp}.pdf'
        report_path = os.path.join('stored_reports', filename)  # Changed to stored_reports

        # Generate log report
        generate_log_report(data, report_path)

        # Store in scan history
        scan_id = store_scan_history(data, report_path)

        # Send file
        response = send_file(
            report_path,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )

        return response

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-history', methods=['GET'])
def get_scan_history():
    """Retrieve scan history"""
    try:
        history = []
        for file in os.listdir(SCAN_HISTORY_DIR):
            if file.endswith('.json'):
                with open(os.path.join(SCAN_HISTORY_DIR, file)) as f:
                    history.append(json.load(f))
        return jsonify(sorted(history, key=lambda x: x['timestamp'], reverse=True))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Make sure Flask server accepts connections from any host
if __name__ == '__main__':
    # Enable debug mode and allow external connections
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
