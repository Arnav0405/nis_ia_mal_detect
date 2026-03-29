import os
import re
import json
import yara
import hashlib
import pefile
import olefile
import zipfile
import magic
import requests
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import gradio as gr
import oletools.olevba as olevba
import PyPDF2

class MalwareBazaarAPI:
    def __init__(self, api_key: str):
        self.api_url = "https://mb-api.abuse.ch/api/v1/"
        self.headers = {"API-KEY": api_key} if api_key else {}

    def _make_request(self, data: Dict) -> Optional[Dict]:
        try:
            response = requests.post(self.api_url, data=data, headers=self.headers, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"MalwareBazaar API error: {e}")
            return None

    def query_hash(self, file_hash: str) -> Optional[Dict]:
        return self._make_request({"query": "get_info", "hash": file_hash})

    def query_tag(self, tag: str) -> Optional[Dict]:
        return self._make_request({"query": "get_taginfo", "tag": tag})

    def query_signature(self, signature: str) -> Optional[Dict]:
        return self._make_request({"query": "get_siginfo", "signature": signature})

    def query_filetype(self, ftype: str) -> Optional[Dict]:
        return self._make_request({"query": "get_file_type", "file_type": ftype})

    def query_clamav(self, clamav: str) -> Optional[Dict]:
        return self._make_request({"query": "get_clamavinfo", "clamav": clamav})

    def query_imphash(self, imphash: str) -> Optional[Dict]:
        return self._make_request({"query": "get_imphash", "imphash": imphash})

    def query_tlsh(self, tlsh: str) -> Optional[Dict]:
        return self._make_request({"query": "get_tlsh", "tlsh": tlsh})

    def query_telfhash(self, telfhash: str) -> Optional[Dict]:
        return self._make_request({"query": "get_telfhash", "telfhash": telfhash})

    def query_yara_rule(self, yara_rule: str) -> Optional[Dict]:
        return self._make_request({"query": "get_yarainfo", "yara_rule": yara_rule})


class StaticAnalyzer:
    def __init__(self, yara_rules_path: str = "yara_rules", mb_api_key: str = None):
        self.file_info = {}
        self.magic = magic.Magic(mime=True)
        self.yara_rules = self._load_yara_rules(yara_rules_path)
        self.mb_api = MalwareBazaarAPI(mb_api_key) if mb_api_key else None
        self.string_min_length = 4

    def _load_yara_rules(self, rules_path: str) -> Optional[yara.Rules]:
        if not os.path.exists(rules_path):
            return None
        try:
            return yara.compile(rules_path)
        except Exception as e:
            print(f"Error loading YARA rules: {e}")
            return None

    def _get_file_type(self, file_path: str) -> str:
        try:
            return self.magic.from_file(file_path)
        except:
            return "Unknown"

    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        hashes = {}
        buf_size = 65536
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(buf_size):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        hashes['md5'] = md5.hexdigest()
        hashes['sha1'] = sha1.hexdigest()
        hashes['sha256'] = sha256.hexdigest()
        return hashes

    def _detailed_string_analysis(self, file_path: str):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                strings = re.findall(rb"[ -~]{%d,}" % self.string_min_length, data)
                decoded_strings = [s.decode('utf-8', errors='ignore') for s in strings]
                self.file_info['analysis']['strings'] = decoded_strings[:100]

                iocs = {
                    'urls': re.findall(r'https?://[^\s"<>]+', " ".join(decoded_strings)),
                    'ips': re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', " ".join(decoded_strings)),
                    'emails': re.findall(r'[\w\.-]+@[\w\.-]+', " ".join(decoded_strings)),
                    'registry_keys': re.findall(r'HKEY_[A-Z_]+\\[\w\\]+', " ".join(decoded_strings), re.IGNORECASE),
                    'file_paths': re.findall(r'[a-zA-Z]:\\\\[\w\\\.]+', " ".join(decoded_strings))
                }
                self.file_info['analysis']['iocs'] = iocs

                if file_path.lower().endswith(('.doc', '.docx', '.xls', '.ppt', '.xlsm', '.docm')):
                    self._analyze_office_macros(file_path)
                elif file_path.lower().endswith('.pdf'):
                    self._analyze_pdf_macros(file_path)

        except Exception as e:
            self.file_info['analysis']['strings'] = {'error': str(e)}

    def _analyze_office_macros(self, file_path: str):
        try:
            vbaparser = olevba.VBA_Parser(file_path)
            if vbaparser.detect_vba_macros():
                macro_summary = []
                for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                    macro_summary.append(vba_code[:200])  # Preview first 200 chars
                self.file_info['analysis']['office_macros'] = macro_summary
            vbaparser.close()
        except Exception as e:
            self.file_info['analysis']['office_macros'] = {'error': str(e)}

    def _analyze_pdf_macros(self, file_path: str):
        try:
            with open(file_path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                javascript = []
                for page in reader.pages:
                    if '/AA' in page or '/JS' in page:
                        javascript.append(str(page))
                self.file_info['analysis']['pdf_macros'] = javascript[:3]
        except Exception as e:
            self.file_info['analysis']['pdf_macros'] = {'error': str(e)}

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        self.file_info = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': os.path.getsize(file_path),
            'file_type': self._get_file_type(file_path),
            'hashes': self._calculate_hashes(file_path),
            'analysis': {}
        }
        self._detailed_string_analysis(file_path)
        return self.file_info

def gradio_interface(file_objs, output_format, mb_api_key, query_type, query_value):
    file_paths = [f.name for f in file_objs] if file_objs else []
    if query_value and mb_api_key:
        mb_api = MalwareBazaarAPI(mb_api_key)
        all_methods = [
            mb_api.query_hash,
            mb_api.query_tag,
            mb_api.query_signature,
            mb_api.query_filetype,
            mb_api.query_clamav,
            mb_api.query_imphash,
            mb_api.query_tlsh,
            mb_api.query_telfhash,
            mb_api.query_yara_rule,
        ]
        all_results = {}
        for method in all_methods:
            try:
                result = method(query_value)
                if result and result.get('query_status') == 'ok':
                    all_results[method.__name__] = result
            except Exception as e:
                all_results[method.__name__] = {'error': str(e)}
        return json.dumps(all_results, indent=2) if output_format == 'json' else str(all_results)
    return json.dumps([StaticAnalyzer(mb_api_key).analyze_file(p) for p in file_paths], indent=2)

def format_mb_query_result(result: Dict) -> str:
    if not result or 'query_status' not in result:
        return "No results or invalid response"
    if result['query_status'] != 'ok':
        return f"Query failed: {result['query_status']}"
    text_output = []
    data = result.get('data', [])
    if not data:
        return "No matching samples found"
    for sample in data[:5]:
        text_output.append(f"SHA256: {sample.get('sha256_hash', 'N/A')}")
        text_output.append(f"Filename: {sample.get('file_name', 'N/A')}")
        text_output.append(f"Type: {sample.get('file_type', 'N/A')}")
        text_output.append(f"Signature: {sample.get('signature', 'N/A')}")
        text_output.append(f"First Seen: {sample.get('first_seen', 'N/A')}")
        text_output.append(f"Tags: {', '.join(sample.get('tags', [])) if sample.get('tags') else 'N/A'}")
        text_output.append("=" * 30)
    return "\n".join(text_output)

if __name__ == "__main__":
    with gr.Blocks(title="Static Malware Analyzer") as demo:
        gr.Markdown("# Static Malware Analyzer")
        gr.Markdown("Upload files for analysis or query MalwareBazaar directly")
        with gr.Row():
            with gr.Column():
                file_input = gr.Files(label="Select files")
                mb_api_key = gr.Textbox(label="MalwareBazaar API Key (optional)", type="password")
                format_radio = gr.Radio(["json", "text"], label="Output Format", value="json")
                query_type = gr.Textbox(label="Query Type (ignored)")
                query_value = gr.Textbox(label="Query Value")
            output = gr.Textbox(label="Analysis Results", lines=25)
        analyze_btn = gr.Button("Analyze/Query")
        analyze_btn.click(fn=gradio_interface, inputs=[file_input, format_radio, mb_api_key, query_type, query_value], outputs=output)
    demo.launch()

