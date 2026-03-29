import os
import re
import json
import yara
import hashlib
import pefile
import olefile
import zipfile
import magic
import pdfminer
from pathlib import Path
from typing import Dict, Any, List, Optional
import gradio as gr

class StaticAnalyzer:
    def __init__(self, yara_rules_path: str = "yara_rules"):
        self.file_info = {}
        self.magic = magic.Magic(mime=True)
        self.yara_rules = self._load_yara_rules(yara_rules_path)
        self.string_min_length = 4

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Main analysis function that routes to specific analyzers"""
        self.file_info = {
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': os.path.getsize(file_path),
            'file_type': self._get_file_type(file_path),
            'hashes': self._calculate_hashes(file_path),
            'analysis': {}
        }
        
        # Enhanced file type routing
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext in ('.exe', '.dll', '.sys'):
            self._analyze_pe(file_path)
        elif file_ext == '.elf':
            self._analyze_elf(file_path)
        elif file_ext == '.apk':
            self._analyze_apk(file_path)
        elif file_ext in ('.doc', '.xls', '.ppt', '.docx', '.xlsx', '.pptx'):
            self._analyze_office(file_path)
        elif file_ext in ('.zip', '.rar', '.7z', '.jar'):
            self._analyze_archive(file_path)
        elif file_ext == '.pdf':
            self._analyze_pdf(file_path)
        elif file_ext == '.ps1':
            self._analyze_ps1(file_path)
        elif file_ext == '.sh':
            self._analyze_sh(file_path)
        elif file_ext in ('.macho', '.dylib'):
            self._analyze_macho(file_path)
        else:
            self._generic_analysis(file_path)
        
        # Common analyses
        self._yara_scan(file_path)
        self._detailed_string_analysis(file_path)
        
        return self.file_info

    def _get_file_type(self, file_path: str) -> str:
        """Improved file type detection with custom signatures"""
        try:
            # Check magic numbers first
            with open(file_path, 'rb') as f:
                header = f.read(32)
                
            if header.startswith(b'MZ'):
                return 'PE executable'
            elif header.startswith(b'\x7fELF'):
                return 'ELF executable'
            elif header.startswith(b'%PDF'):
                return 'PDF document'
            elif header.startswith((b'\xD0\xCF\x11\xE0', b'\x50\x4B\x03\x04')):
                return 'Office document'
            elif header.startswith(b'\x52\x61\x72\x21'):
                return 'RAR archive'
            elif header.startswith(b'7z\xBC\xAF\x27\x1C'):
                return '7z archive'
                
            # Fall back to python-magic
            return self.magic.from_file(file_path)
        except:
            return "Unknown"

    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate common file hashes"""
        hashes = {}
        buf_size = 65536  # 64kb chunks
        
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(buf_size)
                if not data:
                    break
                md5.update(data)
                sha1.update(data)
                sha256.update(data)
        
        hashes['md5'] = md5.hexdigest()
        hashes['sha1'] = sha1.hexdigest()
        hashes['sha256'] = sha256.hexdigest()
        
        return hashes

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

    def _analyze_elf(self, file_path: str):
        """ELF binary analysis"""
        try:
            import lief
            elf = lief.parse(file_path)
            elf_info = {
                'header': {
                    'type': str(elf.header.file_type),
                    'machine': str(elf.header.machine_type),
                    'entry_point': hex(elf.header.entrypoint)
                },
                'sections': [{
                    'name': sec.name,
                    'size': sec.size,
                    'entropy': sec.entropy
                } for sec in elf.sections]
            }
            self.file_info['analysis']['elf'] = elf_info
        except Exception as e:
            self.file_info['analysis']['elf'] = {'error': str(e)}

    def _analyze_apk(self, file_path: str):
        """Android APK analysis"""
        try:
            from androguard.core.bytecodes.apk import APK
            apk = APK(file_path)
            apk_info = {
                'package': apk.get_package(),
                'permissions': apk.get_permissions(),
                'activities': apk.get_activities(),
                'services': apk.get_services(),
                'receivers': apk.get_receivers()
            }
            self.file_info['analysis']['apk'] = apk_info
        except Exception as e:
            self.file_info['analysis']['apk'] = {'error': str(e)}

    def _analyze_office(self, file_path: str):
        """Enhanced Office document analysis"""
        try:
            office_info = {}
            if file_path.endswith(('.doc', '.xls', '.ppt')):
                # OLE-based formats
                ole = olefile.OleFileIO(file_path)
                office_info['metadata'] = ole.get_metadata()
                office_info['streams'] = ole.listdir()
                ole.close()
                
                # Macro analysis
                if file_path.endswith('.doc'):
                    self._analyze_word_macros(file_path)
                    
            elif file_path.endswith(('.docx', '.xlsx', '.pptx')):
                # Office Open XML formats
                with zipfile.ZipFile(file_path) as z:
                    office_info['files'] = [f for f in z.namelist() 
                                          if 'macros' in f.lower() or 'vba' in f.lower()]
                    
            self.file_info['analysis']['office'] = office_info
        except Exception as e:
            self.file_info['analysis']['office'] = {'error': str(e)}

    def _analyze_archive(self, file_path: str):
        """Handle common archive formats"""
        try:
            archive_info = {}
            if file_path.endswith(('.zip', '.jar')):
                with zipfile.ZipFile(file_path) as z:
                    archive_info['files'] = z.namelist()
                    archive_info['comments'] = z.comment.decode('utf-8', errors='ignore')
            elif file_path.endswith('.rar'):
                import rarfile
                with rarfile.RarFile(file_path) as r:
                    archive_info['files'] = r.namelist()
                    archive_info['comments'] = r.comment
            elif file_path.endswith('.7z'):
                import py7zr
                with py7zr.SevenZipFile(file_path) as sz:
                    archive_info['files'] = sz.getnames()
            
            self.file_info['analysis']['archive'] = archive_info
        except Exception as e:
            self.file_info['analysis']['archive'] = {'error': str(e)}

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

    def _analyze_macho(self, file_path: str):
        """MacOS Mach-O binary analysis"""
        try:
            import lief
            macho = lief.parse(file_path)
            macho_info = {
                'header': {
                    'cpu_type': str(macho.header.cpu_type),
                    'file_type': str(macho.header.file_type)
                },
                'commands': [{
                    'command': str(cmd.command),
                    'size': cmd.size
                } for cmd in macho.commands]
            }
            self.file_info['analysis']['macho'] = macho_info
        except Exception as e:
            self.file_info['analysis']['macho'] = {'error': str(e)}

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

    def _load_yara_rules(self, rules_path: str) -> Optional[yara.Rules]:
        """Compile YARA rules from directory"""
        if not os.path.exists(rules_path):
            return None
            
        try:
            return yara.compile(rules_path)
        except Exception as e:
            print(f"Error loading YARA rules: {e}")
            return None

def analyze_files(file_paths: List[str], output_format: str = 'json') -> str:
    """Analyze one or more files and return results in specified format"""
    analyzer = StaticAnalyzer()
    results = []
    
    for file_path in file_paths:
        if not os.path.exists(file_path):
            results.append({'error': f'File not found: {file_path}'})
            continue
        
        try:
            result = analyzer.analyze_file(file_path)
            results.append(result)
        except Exception as e:
            results.append({'error': str(e), 'file_path': file_path})
    
    if output_format == 'json':
        return json.dumps(results, indent=2)
    else:  # text format
        text_output = []
        for result in results:
            if 'error' in result:
                text_output.append(f"Error analyzing {result.get('file_path', 'unknown')}: {result['error']}")
                continue
            
            text_output.append(f"File: {result['file_name']}")
            text_output.append(f"Size: {result['file_size']} bytes")
            text_output.append(f"Type: {result['file_type']}")
            text_output.append("Hashes:")
            text_output.append(f"  MD5:    {result['hashes']['md5']}")
            text_output.append(f"  SHA1:   {result['hashes']['sha1']}")
            text_output.append(f"  SHA256: {result['hashes']['sha256']}")
            
            # Format-specific output
            if 'pe_header' in result['analysis']:
                pe = result['analysis']['pe_header']
                if 'error' in pe:
                    text_output.append(f"PE Analysis Error: {pe['error']}")
                else:
                    text_output.append("\nPE Header Analysis:")
                    text_output.append(f"  Machine: {pe['machine']}")
                    text_output.append(f"  Sections: {pe['number_of_sections']}")
                    text_output.append(f"  Entry Point: {pe['entry_point']}")
                    text_output.append(f"  Image Base: {pe['image_base']}")
                    
                    text_output.append("\nSections:")
                    for section in pe['sections']:
                        text_output.append(f"  {section['name']}: VA={section['virtual_address']}, Size={section['virtual_size']}, Entropy={section['entropy']:.2f}")
            
            if 'yara' in result['analysis']:
                yara_matches = result['analysis']['yara']
                if 'error' in yara_matches:
                    text_output.append(f"\nYARA Error: {yara_matches['error']}")
                elif yara_matches:
                    text_output.append("\nYARA Matches:")
                    for match in yara_matches:
                        text_output.append(f"  Rule: {match['rule']}")
                        if match['tags']:
                            text_output.append(f"    Tags: {', '.join(match['tags'])}")
            
            text_output.append("\n" + "="*50 + "\n")
        
        return "\n".join(text_output)

# Gradio UI
def gradio_interface(file_objs, output_format):
    file_paths = []
    for file_obj in file_objs:
        file_paths.append(file_obj.name)
    
    return analyze_files(file_paths, output_format)

if __name__ == "__main__":
    with gr.Blocks(title="Static Malware Analyzer") as demo:
        gr.Markdown("# Static Malware Analyzer")
        gr.Markdown("Upload files for static analysis (EXE, DLL, PDF, DOCX, APK, etc.)")
        
        with gr.Row():
            file_input = gr.Files(label="Select files", file_types=[
                ".exe", ".dll", ".sys", ".elf", ".macho", ".dylib", 
                ".ps1", ".sh", ".pdf", ".txt", ".csv", ".xlsx", ".docx",
                ".apk", ".zip", ".rar", ".7z", ".jar"
            ])
            format_radio = gr.Radio(["json", "text"], label="Output Format", value="json")
        
        analyze_btn = gr.Button("Analyze")
        output = gr.Textbox(label="Analysis Results", lines=20, interactive=False)
        
        analyze_btn.click(
            fn=gradio_interface,
            inputs=[file_input, format_radio],
            outputs=output
        )
    
    demo.launch()
