import os
import re
import json
import hashlib
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional
import time
import logging
import gradio as gr

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Optional imports with fallbacks
try:
    import yara
except ImportError:
    logger.warning("yara-python not installed. YARA scanning will be disabled.")
    yara = None

try:
    import magic
except ImportError:
    logger.warning("python-magic not installed. Using basic file type detection.")
    magic = None

try:
    import pefile
except ImportError:
    logger.warning("pefile not installed. PE analysis will be limited.")
    pefile = None

try:
    import olefile
except ImportError:
    logger.warning("olefile not installed. OLE analysis will be disabled.")
    olefile = None

class StaticAnalyzer:
    def __init__(self, yara_rules_path: str = "yara_rules"):
        self.file_info = {}
        self._init_magic()
        self.yara_rules = self._load_yara_rules(yara_rules_path) if yara else None
        self.string_min_length = 4
        self._cache = {}
        
    def _init_magic(self):
        """Initialize magic with fallback"""
        if magic:
            try:
                self.magic = magic.Magic(mime=True)
            except Exception as e:
                logger.error(f"Failed to initialize magic: {e}")
                self.magic = None
        else:
            self.magic = None

    def _get_file_type(self, file_path: str) -> str:
        """Optimized file type detection with caching"""
        if file_path in self._cache:
            return self._cache[file_path]['file_type']
            
        if self.magic:
            try:
                file_type = self.magic.from_file(file_path)
            except Exception:
                file_type = self._fallback_file_type(file_path)
        else:
            file_type = self._fallback_file_type(file_path)
            
        self._cache[file_path] = {'file_type': file_type}
        return file_type

    def _fallback_file_type(self, file_path: str) -> str:
        """Fallback file type detection using file extension and headers"""
        ext = Path(file_path).suffix.lower()
        with open(file_path, 'rb') as f:
            header = f.read(8)
            
        if header.startswith(b'MZ'):
            return 'PE32 executable'
        elif header.startswith(b'%PDF'):
            return 'PDF document'
        elif header.startswith(b'PK'):
            return 'Zip archive'
        else:
            return f'Unknown ({ext})'

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Main analysis function with performance monitoring"""
        start_time = time.time()
        
        try:
            self.file_info = {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'file_size': os.path.getsize(file_path),
                'file_type': self._get_file_type(file_path),
                'hashes': self._calculate_hashes(file_path),
                'analysis': {},
                'performance': {}
            }
            
            # Route to appropriate analyzer with timing
            analyzers = {
                'PE32': self._analyze_pe,
                'Microsoft OLE2': self._analyze_ole,
                'Zip': self._analyze_zip,
                'PDF': self._analyze_pdf,
                'text/x-shellscript': self._analyze_sh,
                '.ps1': self._analyze_ps1
            }
            
            file_type = self.file_info['file_type']
            for type_key, analyzer in analyzers.items():
                if type_key in file_type:
                    self._timed_execution(analyzer, file_path, type_key)
                    
            # Common analyses
            if self.yara_rules:
                self._timed_execution(self._yara_scan, file_path, 'yara')
            self._timed_execution(self._detailed_string_analysis, file_path, 'strings')
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            self.file_info['error'] = str(e)
            
        self.file_info['performance']['total_time'] = time.time() - start_time
        return self.file_info

    def _timed_execution(self, func, *args, name=None):
        """Execute function with timing"""
        start = time.time()
        try:
            func(*args)
        except Exception as e:
            logger.error(f"Error in {name or func.__name__}: {e}")
            self.file_info['analysis'][name or func.__name__] = {'error': str(e)}
        finally:
            self.file_info['performance'][name or func.__name__] = time.time() - start

    def _analyze_pe(self, file_path: str):
        """Enhanced PE analysis with entropy and malware patterns"""
        try:
            pe = pefile.PE(file_path)
            pe_info = {}
            
            # Basic PE info
            pe_info['machine'] = pe.FILE_HEADER.Machine
            pe_info['number_of_sections'] = pe.FILE_HEADER.NumberOfSections
            pe_info['timestamp'] = pe.FILE_HEADER.TimeDateStamp
            pe_info['entry_point'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            pe_info['image_base'] = pe.OPTIONAL_HEADER.ImageBase
            pe_info['subsystem'] = pe.OPTIONAL_HEADER.Subsystem
            pe_info['dll_characteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
            pe_info['checksum'] = pe.OPTIONAL_HEADER.CheckSum
            pe_info['linker_version'] = f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
            
            # Malware pattern detection
            pe_info['suspicious'] = {
                'packed': False,
                'injected': False,
                'antidebug': False,
                'suspicious_sections': [],
                'suspicious_imports': []
            }
            
            # Section analysis with entropy
            pe_info['sections'] = []
            entropy_threshold = 7.0  # Typical packed/encrypted content threshold
            for section in pe.sections:
                sec_info = {
                    'name': section.Name.decode('utf-8').strip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': hex(section.Misc_VirtualSize),
                    'raw_size': hex(section.SizeOfRawData),
                    'entropy': section.get_entropy(),
                    'characteristics': hex(section.Characteristics)
                }
                pe_info['sections'].append(sec_info)
                
                # Check for packed sections
                if sec_info['entropy'] > entropy_threshold:
                    pe_info['suspicious']['packed'] = True
                    pe_info['suspicious']['suspicious_sections'].append(
                        f"High entropy ({sec_info['entropy']:.2f}) in section {sec_info['name']}")
                
                # Check known malicious section names
                suspicious_section_names = ['.vmp','.crack','.pack','.textbss']
                if any(name in sec_info['name'].lower() for name in suspicious_section_names):
                    pe_info['suspicious']['suspicious_sections'].append(
                        f"Suspicious section name: {sec_info['name']}")

            # Import analysis
            suspicious_imports = {
                'VirtualAlloc', 'VirtualProtect', 'CreateRemoteThread',
                'ProcessInject', 'WriteProcessMemory', 'SetWindowsHookEx'
            }
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name and imp.name.decode() in suspicious_imports:
                            pe_info['suspicious']['suspicious_imports'].append(
                                f"Suspicious import: {imp.name.decode()}")
                            pe_info['suspicious']['injected'] = True

            self.file_info['analysis']['pe_header'] = pe_info
            pe.close()
            
        except Exception as e:
            self.file_info['analysis']['pe_header'] = {'error': str(e)}

    def _analyze_pdf(self, file_path: str):
        """Basic PDF analysis looking for JavaScript and embedded objects"""
        pdf_info = {}
        try:
            with open(file_path, 'rb') as f:
                content = f.read(4096)  # Read first 4KB for quick analysis
                
            # Look for PDF keywords (based on pdfid)
            patterns = {
                'javascript': rb'/JS',
                'embedded_file': rb'/EmbeddedFile',
                'auto_action': rb'/AA',
                'launch_action': rb'/Launch',
                'ifilter': rb'/ObjStm'
            }
            
            pdf_info['suspicious'] = {}
            for name, pattern in patterns.items():
                count = len(re.findall(pattern, content, re.IGNORECASE))
                if count > 0:
                    pdf_info['suspicious'][name] = count
                    
            self.file_info['analysis']['pdf'] = pdf_info
        except Exception as e:
            self.file_info['analysis']['pdf'] = {'error': str(e)}

    def _analyze_ps1(self, file_path: str):
        """PowerShell script analysis"""
        ps_info = {}
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                
            ps_info['suspicious'] = {
                'obfuscation_score': 0,
                'long_lines': 0,
                'encoded_strings': 0,
                'suspicious_cmdlets': []
            }
            
            # Check for common obfuscation techniques
            if len(content) > 0:
                avg_line_length = len(content) / (content.count('\n') + 1)
                if avg_line_length > 200:
                    ps_info['suspicious']['long_lines'] = avg_line_length
                    ps_info['suspicious']['obfuscation_score'] += 1
                    
                # Detect encoded commands
                encoded_patterns = [
                    r'-EncodedCommand\s+',
                    r'FromBase64String\(',
                    r'\-e\s+'
                ]
                for pattern in encoded_patterns:
                    if re.search(pattern, content):
                        ps_info['suspicious']['encoded_strings'] += 1
                        ps_info['suspicious']['obfuscation_score'] += 1
                        
                # Suspicious cmdlets
                bad_cmdlets = [
                    'Invoke-Expression', 'DownloadFile', 'Start-Process',
                    'New-Object System.Net.WebClient'
                ]
                for cmdlet in bad_cmdlets:
                    if cmdlet in content:
                        ps_info['suspicious']['suspicious_cmdlets'].append(cmdlet)
                        ps_info['suspicious']['obfuscation_score'] += 1
                        
            self.file_info['analysis']['powershell'] = ps_info
        except Exception as e:
            self.file_info['analysis']['powershell'] = {'error': str(e)}

    def _yara_scan(self, file_path: str):
        """Perform YARA rule scanning"""
        if not self.yara_rules:
            return
            
        try:
            matches = []
            with open(file_path, 'rb') as f:
                matches = self.yara_rules.match(data=f.read())
                
            self.file_info['analysis']['yara'] = [
                {
                    'rule': match.rule,
                    'tags': match.tags,
                    'meta': match.meta
                } for match in matches
            ]
        except Exception as e:
            self.file_info['analysis']['yara'] = {'error': str(e)}

    def _detailed_string_analysis(self, file_path: str):
        """Enhanced string analysis with pattern matching"""
        try:
            # Extract all strings
            strings = self._extract_all_strings(file_path)
            
            # Find interesting patterns
            patterns = {
                'urls': r'https?://[^\s/$.?#].[^\s]*',
                'ips': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                'exec_patterns': [
                    'CreateRemoteThread', 'VirtualAlloc', 'WinExec',
                    'reg add', 'netsh', 'powershell.exe -'
                ]
            }
            
            findings = {'count': len(strings), 'suspicious': {}}
            for name, pattern in patterns.items():
                if isinstance(pattern, list):
                    for item in pattern:
                        matches = [s for s in strings if item.lower() in s.lower()]
                        if matches:
                            findings['suspicious'][item] = matches[:5]  # Show first 5 matches
                else:
                    matches = re.findall(pattern, ' '.join(strings))
                    if matches:
                        findings['suspicious'][name] = list(set(matches))[:5]
            
            self.file_info['analysis']['strings'] = findings
        except Exception as e:
            self.file_info['analysis']['strings'] = {'error': str(e)}

    def _extract_all_strings(self, file_path: str) -> List[str]:
        """Extract all ASCII strings from file"""
        try:
            # Use system strings command for better performance
            if os.name == 'posix':
                return os.popen(f'strings "{file_path}"').read().splitlines()
            else:
                # Fallback method for Windows
                with open(file_path, 'rb') as f:
                    content = f.read()
                return self._extract_strings(content, self.string_min_length)
        except:
            return []

    def _extract_strings(self, data: bytes, min_length: int) -> List[str]:
        """Extract ASCII and Unicode strings from binary data"""
        result = []
        pattern = f'[A-Za-z0-9/\-:.,_$%\'()[\]{{}} ]{{{min_length},}}'
        result.extend(re.findall(pattern.encode('ascii'), data))
        # Convert bytes to strings and clean
        return [s.decode('ascii', errors='ignore').strip() for s in result]

    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes efficiently using chunks"""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        chunk_size = 8192  # 8KB chunks for memory efficiency
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest()
        }

    def _load_yara_rules(self, rules_path: str) -> Optional[yara.Rules]:
        """Compile YARA rules from directory"""
        if not os.path.exists(rules_path):
            return None
            
        try:
            return yara.compile(rules_path)
        except Exception as e:
            print(f"Error loading YARA rules: {e}")
            return None

def analyze_files(files):
    """Analyze multiple files and return results"""
    analyzer = StaticAnalyzer()
    results = []
    
    for file in files:
        try:
            result = analyzer.analyze_file(file.name)
            results.append(result)
        except Exception as e:
            results.append({
                'file_path': file.name,
                'error': str(e)
            })
    
    return json.dumps(results, indent=2)

# Gradio interface
def create_gradio_interface():
    """Create and launch the Gradio interface"""
    iface = gr.Interface(
        fn=analyze_files,
        inputs=gr.File(file_count="multiple"),
        outputs=gr.JSON(),
        title="Static File Analyzer",
        description="Upload files for static analysis",
        examples=[],
        cache_examples=False
    )
    return iface

if __name__ == "__main__":
    iface = create_gradio_interface()
    iface.launch(share=False)