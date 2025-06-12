
"""

    This code has been corrected and fixed from the original shitbox mess,
    Its still aweful, But its a slight improvement. - rep

"""


import winreg
import csv
import os
import re
import subprocess
import datetime
import time
import sys
import psutil
import ctypes
from datetime import datetime, timedelta
from colorama import Fore, Style, init
import glob
import struct
from collections import defaultdict
from pathlib import Path
import xml.etree.ElementTree as ET
import urllib.request
from win32com.shell import shell, shellcon
from ctypes import wintypes

# Initialize Colorama for colored output
init()

# Global Constants
CSV_OUT = 'C:\\bypass_generics.csv'
JOURNAL_CSV = 'C:\\SS\\MFTECmd\\USNJRNL.fullPaths.csv'

# ctypes for Windows API calls (Decompression functions) - Note: These are defined but not used in the provided logic
ntdll = ctypes.WinDLL('ntdll.dll')
RtlGetCompressionWorkSpaceSize = ntdll.RtlGetCompressionWorkSpaceSize
RtlGetCompressionWorkSpaceSize.argtypes = [wintypes.USHORT, ctypes.POINTER(wintypes.ULONG), ctypes.POINTER(wintypes.ULONG)]
RtlGetCompressionWorkSpaceSize.restype = wintypes.LONG
RtlDecompressBufferEx = ntdll.RtlDecompressBufferEx
RtlDecompressBufferEx.argtypes = [wintypes.USHORT, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG), ctypes.c_void_p]
RtlDecompressBufferEx.restype = wintypes.LONG

# Placeholder for Prefetch parsing (you'll need a proper library for this if detailed parsing is required)
class Prefetch:
    """
    A minimal placeholder class for Prefetch file data.
    For comprehensive Prefetch parsing, consider using a dedicated library
    like 'python-prefetch' or implement a full parser.
    """
    def __init__(self, path):
        self.path = path
        self.executableName = os.path.basename(path).replace('.pf', '')
        self.runCount = 1 # Dummy value
        self.lastRunTime = datetime.now() # Dummy value
        self.resources = [] # Dummy list for DLLs and other resources

    def __str__(self):
        return f"Prefetch(Executable: {self.executableName}, Path: {self.path})"

# Import ssdeep if available
try:
    import ssdeep
except ImportError:
    print("WARNING: 'ssdeep' library not found. Impfuzzy generation and comparison will be disabled.")
    ssdeep = None

# ---
# Utility Functions
# ---

def clean_text(raw_text):
    """Removes non-printable ASCII characters from a string."""
    return ''.join((c for c in raw_text if 33 <= ord(c) <= 126))

def is_ascii(s):
    """Checks if a string contains only ASCII characters."""
    return all((ord(c) < 128 for c in s))

def has_unicode(s):
    """Checks if a string contains any Unicode characters."""
    return not is_ascii(s)

def find_unicode(s):
    """Finds and returns a list of Unicode characters in a string with their hex codes."""
    unicode_chars = []
    for char in s:
        if ord(char) >= 128:
            char_hex = f'U+{ord(char):04X}'
            char_name = f'{char} ({char_hex})'
            unicode_chars.append(char_name)
    return unicode_chars

def rar_regex(file_path):
    """Checks if a file path matches a temporary RAR archive pattern."""
    rar_pattern = r'\\Temp\\Rar\$[^\\\\]+\.rartemp\\'
    return bool(re.search(rar_pattern, file_path, re.IGNORECASE))

def filetime_datetime(filetime):
    """Converts Windows FILETIME to a datetime object."""
    EPOCH_AS_FILETIME = 116444736000000000 # January 1, 1970 (UTC) as FILETIME
    timestamp = (filetime - EPOCH_AS_FILETIME) / 10000000.0
    try:
        from datetime import timezone
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).replace(tzinfo=None)
    except ImportError:
        return datetime.utcfromtimestamp(timestamp)

def get_boot_time():
    """Retrieves the system's last boot time."""
    try:
        return datetime.fromtimestamp(psutil.boot_time())
    except ImportError:
        try:
            import wmi # This import was missing in the original, but used here
            c = wmi.WMI()
            for os_info in c.Win32_OperatingSystem():
                boot_time_str = os_info.LastBootUpTime
                return datetime.strptime(boot_time_str.split('.')[0], '%Y%m%d%H%M%S')
        except ImportError:
            print(f"{Fore.YELLOW}WARNING: 'wmi' library not found. Cannot get boot time via WMI.{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.RED}Error getting boot time: {e}{Style.RESET_ALL}")
            return None

def parse_csv_timestamp(timestamp_str):
    """Parses a timestamp string from CSV format to a datetime object."""
    try:
        return datetime.strptime(timestamp_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
    except (ValueError, AttributeError):
        return None

def read_journal_csv():
    """Reads and parses the USN Journal CSV file."""
    if not os.path.exists(JOURNAL_CSV):
        print(f"{Fore.YELLOW}Journal CSV not found: {JOURNAL_CSV}. Please ensure MFTECmd has been run.{Style.RESET_ALL}")
        return []
    entries = []
    try:
        with open(JOURNAL_CSV, 'r', encoding='utf-8', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                timestamp = parse_csv_timestamp(row.get('UpdateTimestamp', ''))
                if timestamp:
                    entry = {
                        'file_name': row.get('Name', ''),
                        'extension': row.get('Extension', ''),
                        'parent_path': row.get('ParentPath', ''),
                        'full_path': os.path.join(row.get('ParentPath', ''), row.get('Name', '')).replace('.\\', ''),
                        'reason': row.get('UpdateReasons', ''),
                        'timestamp': timestamp,
                        'file_attributes': row.get('FileAttributes', '')
                    }
                    entries.append(entry)
    except Exception as e:
        print(f'{Fore.RED}Error reading journal CSV: {e}{Style.RESET_ALL}')
        return []
    return entries

def get_pid(name):
    """Gets the Process ID (PID) of a service or process by name."""
    try:
        # Try getting PID for services first using 'sc queryex'
        result = subprocess.run(['sc', 'queryex', name], capture_output=True, text=True, check=False)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if 'PID' in line:
                    return int(line.split(':')[1].strip())
    except Exception as e:
        print(f"{Fore.YELLOW}Error querying service {name} for PID: {e}{Style.RESET_ALL}")

    # Fallback to 'tasklist' for processes
    try:
        result = subprocess.run(['tasklist', '/fi', f'imagename eq {name}'], capture_output=True, text=True, check=False)
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            for line in lines[3:]: # Skip header lines (usually 3 lines)
                if name.lower() in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1])
    except Exception as e:
        print(f'{Fore.RED}[!] Error querying process {name} for PID: {e}{Style.RESET_ALL}')
    return None

def download_xxstrings():
    """Downloads the xxstrings64.exe tool if not already present."""
    ss_dir = 'C:\\SS'
    xxstrings_path = os.path.join(ss_dir, 'xxstrings64.exe')
    if not os.path.exists(ss_dir):
        os.makedirs(ss_dir, exist_ok=True)
    if not os.path.exists(xxstrings_path):
        url = 'https://github.com/ZaikoARG/xxstrings/releases/download/1.0.0/xxstrings64.exe'
        try:
            print(f"{Fore.BLUE}Downloading xxstrings64.exe from {url}...{Style.RESET_ALL}")
            urllib.request.urlretrieve(url, xxstrings_path)
            print(f"{Fore.GREEN}Download complete.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error downloading xxstrings64.exe: {e}{Style.RESET_ALL}")
            return None
    return xxstrings_path

def delete_file(path):
    """Deletes a file if it exists."""
    if os.path.exists(path):
        try:
            os.remove(path)
            print(f"{Fore.YELLOW}Deleted temporary file: {path}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error deleting file {path}: {e}{Style.RESET_ALL}")

# ---
# Prefetch Analysis Functions
# ---

class PrefetchAnalyzer:
    """
    Handles operations related to parsing and analyzing Prefetch files.
    Requires 'ssdeep' for impfuzzy hashing.
    """
    def extract_dll_list_from_prefetch(self, pf):
        """Extract and sort DLL names from prefetch resources."""
        dll_list = []
        # In a real scenario, pf.resources would be populated by a proper Prefetch parser
        # This placeholder just returns an empty list
        return sorted(dll_list)

    def generate_impfuzzy_from_dll_list(self, dll_list):
        """
        Generate an impfuzzy-style hash from a list of DLL names using ssdeep fuzzy hashing.
        This matches the format: 3:ZZpnRhUrhhp3M2jVuykm1:ZX0B3
        """
        if not dll_list:
            return (None, None)
        if ssdeep is None:
            return (None, None)

        try:
            dll_string = ','.join(dll_list)
            fuzzy_hash = ssdeep.hash(dll_string.encode('utf-8'))
            return (fuzzy_hash, dll_string)
        except Exception as e:
            print(f'{Fore.RED}Error generating impfuzzy hash: {e}{Style.RESET_ALL}')
            return (None, None)

    def compare_impfuzzy_hashes(self, hash1, hash2):
        """
        Compare two impfuzzy hashes using ssdeep fuzzy matching.
        Returns similarity percentage (0-100).
        """
        if not hash1 or not hash2:
            return 0
        if ssdeep is None:
            return 0
        try:
            similarity = ssdeep.compare(hash1, hash2)
            return similarity
        except Exception as e:
            print(f'{Fore.RED}Error comparing impfuzzy hashes: {e}{Style.RESET_ALL}')
            return 0

    def compare_dll_lists(self, dll_list1, dll_list2):
        """
        Compare two DLL lists and return Jaccard similarity percentage.
        """
        if not dll_list1 or not dll_list2:
            return 0
        set1 = set(dll_list1)
        set2 = set(dll_list2)
        intersection = set1.intersection(set2)
        union = set1.union(set2)
        if len(union) == 0:
            return 100.0
        jaccard_similarity = len(intersection) / len(union) * 100
        return jaccard_similarity

    def parse_prefetch_file(self, pf_path):
        """
        Parse a single prefetch file and extract impfuzzy data.
        Note: This uses a placeholder Prefetch class. For real parsing,
        a proper library or implementation is needed.
        """
        try:
            if not os.path.exists(pf_path):
                return None
            file_size = os.path.getsize(pf_path)
            if file_size == 0:
                return None

            pf = Prefetch(pf_path)
            dll_list = self.extract_dll_list_from_prefetch(pf)
            impfuzzy_hash, dll_signature = self.generate_impfuzzy_from_dll_list(dll_list)
            return {
                'path': pf_path,
                'filename': os.path.basename(pf_path),
                'executable': pf.executableName,
                'dll_list': dll_list,
                'dll_signature': dll_signature,
                'impfuzzy': impfuzzy_hash,
                'dll_count': len(dll_list),
                'run_count': pf.runCount,
                'last_run_time': str(pf.lastRunTime),
                'file_size': file_size
            }
        except Exception as e:
            print(f'{Fore.RED}ERROR parsing {pf_path}: {e}{Style.RESET_ALL}')
            return None

    def find_prefetch_files(self):
        """Find all prefetch files in the system."""
        prefetch_paths = []
        possible_paths = ['C:\\Windows\\Prefetch\\*.pf', 'C:\\WINDOWS\\Prefetch\\*.pf', '%WINDIR%\\Prefetch\\*.pf']
        for path_pattern in possible_paths:
            expanded_path = os.path.expandvars(path_pattern)
            files = glob.glob(expanded_path)
            prefetch_paths.extend(files)
        return list(set(prefetch_paths))

# Instantiate PrefetchAnalyzer
prefetch_analyzer = PrefetchAnalyzer()

# Helper functions for PIDs
def get_dps_pid():
    return get_pid('DPS')

def get_eventlog_pid():
    return get_pid('EventLog')

# ---
# Bypass Detection Functions
# ---

def analyze_evtx():
    """Checks for EventLog bypasses based on log file size."""
    print(f'{Fore.LIGHTRED_EX}{Style.BRIGHT}Checking for EventLog bypasses...{Style.RESET_ALL}')
    log_paths = [
        'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx',
        'C:\\Windows\\System32\\winevt\\Logs\\Application.evtx',
        'C:\\Windows\\System32\\winevt\\Logs\\Windows PowerShell.evtx',
        'C:\\Windows\\System32\\winevt\\Logs\\System.evtx'
    ]
    flagged_logs = []
    for log_path in log_paths:
        if os.path.exists(log_path):
            try:
                size_kb = os.path.getsize(log_path) / 1024
                log_name = os.path.basename(log_path)
                if size_kb <= 300:
                    flagged_logs.append({'Bypass Detection': 'EventLog Cleared', 'Detection': log_name, 'Notes': f'Size: {size_kb:.2f} KB (<=300KB)'})
            except Exception as e:
                print(f"{Fore.RED}Error checking size of {log_path}: {e}{Style.RESET_ALL}")
    return flagged_logs

def dll_usage():
    """Looks for possible malicious DLL usage via OpenSavePidlMRU registry key."""
    print(f'{Fore.LIGHTYELLOW_EX}{Style.BRIGHT}Looking for possible malicious DLL usage{Style.RESET_ALL}')
    found = []
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU\\dll')
        i = 0
        while True:
            try:
                name, val, type_id = winreg.EnumValue(key, i)
                if name != 'MRUListEx' and type_id == winreg.REG_BINARY:
                    try:
                        txt = val.decode('utf-16-le', errors='ignore')
                    except UnicodeDecodeError:
                        txt = ''.join((chr(b) if 32 <= b < 127 else ' ' for b in val))

                    if '.dll' in txt.lower():
                        for chunk in re.split(r'\x00+|\s+', txt):
                            if '.dll' in chunk.lower() and chunk.strip():
                                found.append({
                                    'Bypass Detection': 'Possible DLL injection',
                                    'Detection': chunk.strip(),
                                    'Notes': 'Possibly injected / used DLL (Worth investigating)'
                                })
                i += 1
            except OSError:
                break
            except Exception as e:
                print(f"{Fore.RED}Error enumerating registry value at index {i}: {e}{Style.RESET_ALL}")
                i += 1
        winreg.CloseKey(key)
    except FileNotFoundError:
        print(f'{Fore.YELLOW}DLL MRU registry key not found. Skipping DLL usage check.{Style.RESET_ALL}')
    except PermissionError:
        print(f'{Fore.RED}Access denied to DLL MRU registry key. Run as Administrator.{Style.RESET_ALL}')
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred accessing DLL MRU registry key: {e}{Style.RESET_ALL}")
    return found

def anydesk_xfers():
    """Checks AnyDesk file transfer logs for suspicious activities."""
    print(f'{Fore.CYAN}{Style.BRIGHT}Checking AnyDesk transfers...{Style.RESET_ALL}')
    transfers = []
    anydesk_log = 'C:\\ProgramData\\AnyDesk\\file_transfer_trace.txt'
    if not os.path.exists(anydesk_log):
        print(f"{Fore.YELLOW}AnyDesk log not found: {anydesk_log}. Skipping.{Style.RESET_ALL}")
        return []
    try:
        with open(anydesk_log, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                s = clean_text(line)
                if not s.startswith('Clipboard') and not s.startswith('FileManager'):
                    continue

                time_match = re.search(r'(\d{4}-\d{2}-\d{2},\d{2}:\d{2})', s)
                if not time_match:
                    continue

                event = 'unknown'
                if 'startdownload' in s:
                    event = 'start'
                elif 'finishdownload' in s:
                    event = 'finish'

                filename = None
                p = s.find('download\'')
                if p != -1:
                    start = p + len('download\'')
                    end = s.rfind('\'')
                    if end != -1 and end > start:
                        filename = s[start:end].strip()

                if filename:
                    transfers.append({
                        'Bypass Detection': 'AnyDesk File Transfer',
                        'Detection': filename,
                        'Notes': f'{event} download'
                    })
    except IOError as e:
        print(f"{Fore.RED}Error reading AnyDesk log file: {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred during AnyDesk log analysis: {e}{Style.RESET_ALL}")
    return transfers

def read_only():
    """Looks for Read-Only manipulations in the USN Journal."""
    print(f'{Fore.LIGHTGREEN_EX}{Style.BRIGHT}Looking for Read-Only manipulations...{Style.RESET_ALL}')
    entries = read_journal_csv()
    if not entries:
        return []
    sus = []
    patterns = ['nvAppTimestamps', 'ConsoleHost_history', '.pf']
    for entry in entries:
        filename = entry['file_name']
        reason = entry['reason'].lower()
        if any(p in filename for p in patterns) and 'basicinfochange' in reason:
            timestamp = entry['timestamp']
            sus.append({
                'Bypass Detection': 'Read-Only',
                'Detection': filename,
                'Notes': f"The User has put this file to Read-Only to bypass entries written to it at {timestamp.strftime('%H:%M:%S')}"
            })
    return sus

def prefetch_deletion():
    """Checks for deleted prefetch files based on USN Journal entries."""
    print(f'{Fore.RED}{Style.BRIGHT}Running deleted prefetch file checks{Style.RESET_ALL}')
    entries = read_journal_csv()
    if not entries:
        return []
    sus = []
    patterns = ['.pf']
    for entry in entries:
        filename = entry['file_name']
        reason = entry['reason'].lower()
        if any(p in filename for p in patterns) and 'delete' in reason:
            sus.append({
                'Bypass Detection': 'Prefetch File Deleted',
                'Detection': filename,
                'Notes': f"{entry['full_path']} has been deleted, you may be able to ban for this!"
            })
    return sus

def file_replacements():
    """Checks for rapid file replacements by analyzing USN Journal entries."""
    print(f'{Fore.LIGHTMAGENTA_EX}{Style.BRIGHT}Checking for file replacements...{Style.RESET_ALL}')
    entries = read_journal_csv()
    if not entries:
        return []
    file_hist = defaultdict(list)
    suspicious = []
    for entry in entries:
        fname = entry['file_name']
        reason = entry['reason']
        timestamp = entry['timestamp']
        full_path = entry['full_path']
        if fname.lower().endswith(('.exe', '.dll', '.ocx')) and 'rename' in reason.lower():
            file_hist[full_path].append((timestamp, reason, fname))

    for full_path, events in file_hist.items():
        events.sort(key=lambda x: x[0])
        for i in range(len(events) - 1):
            time1, reason1, fname1 = events[i]
            time2, reason2, fname2 = events[i + 1]
            time_diff = (time2 - time1).total_seconds()
            if time_diff <= 10:
                suspicious.append({
                    'Bypass Detection': 'File Replacement',
                    'Detection': fname1,
                    'Notes': 'The User has possibly replaced this file, suggested to check out manually!'
                })
    return suspicious

def detect_modified_files():
    """Detects suspicious file modification patterns in the USN Journal."""
    print(f'{Fore.GREEN}{Style.BRIGHT}Running Generic Modified File Checks (Type A)..{Style.RESET_ALL}')
    entries = read_journal_csv()
    if not entries:
        return []
    file_events = defaultdict(list)
    for entry in entries:
        file_events[entry['full_path']].append(entry)

    flagged = []
    for file_path, events in file_events.items():
        fname = os.path.basename(file_path)
        if 'Rar$EX' in file_path or 'SS\\' in file_path:
            continue
        if not fname.lower().endswith(('.exe', '.dll', '.sys', '.ocx', '.cpl', '.scr', '.drv')):
            continue

        events.sort(key=lambda x: x['timestamp'])

        for i in range(len(events)):
            event1 = events[i]
            reason1 = event1['reason'].lower().replace(' ', '').replace('|', '')
            data_mod_operations = ['dataoverwrite', 'dataextend', 'datatruncation']

            if not any(op in reason1 for op in data_mod_operations):
                continue

            subsequent_operations = []
            for j in range(i + 1, len(events)):
                event2 = events[j]
                time_diff = (event2['timestamp'] - event1['timestamp']).total_seconds()
                if time_diff > 10:
                    break
                reason2 = event2['reason'].lower().replace(' ', '').replace('|', '')
                subsequent_operations.append(reason2)

                detection_type = None
                notes = None

                if 'filedelete' in reason2:
                    detection_type = 'File Modified Then Deleted'
                    notes = f"File was modified then deleted at: {event1['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}"
                elif 'rename' in reason2:
                    detection_type = 'File Modified Then Renamed'
                    notes = f"File was modified then renamed at: {event1['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}"
                elif 'basicinfochange' in reason2 and 'close' in ' '.join(subsequent_operations):
                    detection_type = 'File Modification Pattern'
                    notes = f"Detected modification pattern (BasicInfoChange + Close) at: {event1['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}"
                elif 'securitychange' in reason2:
                    detection_type = 'File Modified With Security Change'
                    notes = f"File modified with security changes at: {event1['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}"

                if detection_type and notes:
                    flagged.append({
                        'Bypass Detection': detection_type,
                        'Detection': fname,
                        'Notes': f'{notes} - Path: {file_path}'
                    })
                    break
    return flagged

def modified_filess():
    """Detects creation, modification, and subsequent deletion of specific file types within a timeframe."""
    print(f'{Fore.GREEN}{Style.BRIGHT}Running Generic Modified File Checks (Type B)..{Style.RESET_ALL}')
    entries = read_journal_csv()
    if not entries:
        return []
    flagged = []
    file_events = defaultdict(list)
    for entry in entries:
        file_events[entry['full_path']].append(entry)

    for file_path, events in file_events.items():
        fname = os.path.basename(file_path)
        if 'Rar$EX' in file_path or 'SS\\' in file_path:
            continue
        if not fname.lower().endswith(('.sys', '.exe')):
            continue

        events.sort(key=lambda x: x['timestamp'])
        create_found = False
        create_time = None
        data_modify_found = False

        for event in events:
            reason = event['reason'].lower()

            if 'filecreate' in reason and not create_found:
                create_found = True
                create_time = event['timestamp']
                continue

            if create_found and not data_modify_found:
                time_diff = (event['timestamp'] - create_time).total_seconds()
                if time_diff > 1200:
                    break
                if any(term in reason for term in ['dataextend', 'datatruncation', 'dataoverwrite']):
                    data_modify_found = True
                    continue

            if create_found and data_modify_found:
                time_diff = (event['timestamp'] - create_time).total_seconds()
                if time_diff > 1200:
                    break
                if 'filedelete' in reason:
                    flagged.append({
                        'Bypass Detection': '[A] Generic File Modification',
                        'Detection': fname,
                        'Notes': f"Suspiciously Modification Pattern detected at: {event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} - Path: {file_path}"
                    })
                    break
    return flagged

def ghost_deletion():
    """Checks for 'ghost deletions' from protected system paths."""
    print(f'{Fore.LIGHTYELLOW_EX}{Style.BRIGHT}Running Ghost Deletion Checks..{Style.RESET_ALL}')
    entries = read_journal_csv()
    if not entries:
        return []
    sus = []
    protected_paths = [
        'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64', 'C:\\Windows\\System32\\drivers',
        'C:\\Windows\\System32\\DriverStore', 'C:\\Windows\\System32\\config', 'C:\\Windows\\System32\\Tasks',
        'C:\\Windows\\System32\\spool', 'C:\\Windows\\Boot', 'C:\\Windows\\Fonts', 'C:\\Windows\\assembly',
        'C:\\Windows\\Microsoft.NET', 'C:\\Windows\\WinSxS'
    ]

    def is_protected_path(parent_path, protected_path_prefix):
        """Checks if parent_path starts with or is an exact match for a protected path."""
        parent_normalized = os.path.normcase(parent_path.replace('/', '\\').rstrip('\\'))
        protected_normalized = os.path.normcase(protected_path_prefix.replace('/', '\\').rstrip('\\'))
        return parent_normalized == protected_normalized or \
               parent_normalized.startswith(protected_normalized + '\\')

    for entry in entries:
        parent_path = entry['parent_path']
        filename = entry['file_name']
        reason = entry['reason'].lower()
        timestamp = entry['timestamp']

        if '.log' in filename.lower():
            continue

        if 'filedelete' in reason:
            for protected_path_prefix in protected_paths:
                if is_protected_path(parent_path, protected_path_prefix):
                    sus.append({
                        'Bypass Detection': 'Ghost Deletion',
                        'Detection': filename,
                        'Notes': f"{filename} was deleted from {parent_path} at {timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
                    })
                    break
    return sus

def analyze_pf():
    """Analyzes recent prefetch files for suspicious program executions."""
    print(f'{Fore.YELLOW}{Style.BRIGHT}Analyzing suspicious files in prefetch...{Style.RESET_ALL}')
    suspicious_keywords = ['systeminformer', 'processhacker', 'regedit', 'curl', 'vscode', 'reg.exe', 'code.exe']
    flagged = []
    pf_folder = 'C:\\Windows\\Prefetch'
    if not os.path.isdir(pf_folder):
        print(f"{Fore.YELLOW}Prefetch folder not found: {pf_folder}. Skipping.{Style.RESET_ALL}")
        return []

    now = datetime.now()
    past = now - timedelta(hours=6)

    files = glob.glob(os.path.join(pf_folder, '*.pf'))
    for f in files:
        try:
            stat = os.stat(f)
            when = max(datetime.fromtimestamp(stat.st_ctime), datetime.fromtimestamp(stat.st_mtime))

            if when < past:
                continue

            name = os.path.basename(f).lower()
            for s in suspicious_keywords:
                if s in name:
                    clean_name = re.sub(r'-[0-9a-f]{8}\.pf', '', name, flags=re.IGNORECASE)
                    flagged.append({
                        'Bypass Detection': 'Suspicious Program Execution (Prefetch)',
                        'Detection': clean_name,
                        'Notes': f"File was executed at: {when.strftime('%Y/%m/%d %H:%M:%S')}. This is borderline suspicious if you did not open this yourself."
                    })
                    break
        except Exception as e:
            print(f"{Fore.RED}Error processing prefetch file {f}: {e}{Style.RESET_ALL}")
    return flagged

def renamed_extensions():
    """Checks for renamed file extensions by analyzing strings in the DPS service memory."""
    print(f'{Fore.LIGHTRED_EX}{Style.BRIGHT}Running modified extensions checks...{Style.RESET_ALL}')
    dps_whitelist = [
        '!!System!1970/01/01:00:00:00!0!', '!!chcp.com!2037/04/02:00:56:27!82a2!',
        '!!Registry!1970/01/01:00:00:00!0!', '!!IsrDpc!1970/01/01:00:00:00!0!',
        '!!Default!1970/01/01:00:00:00!0!', '!!more.com!2074/08/23:02:45:40!ca05!',
        '!!Overflow!1970/01/01:00:00:00!0!', '!!Totals!1970/01/01:00:00:00!0!',
        '!!FiveM_ChromeBrowser!2025/04/17:11:47:40!0!', '!!FiveM_DumpServer!2025/04/17:12:45:27!5008bd!',
        '!!FiveM_ROSService!2025/04/17:11:47:41!0!', '!!FiveM_ROSLauncher!2025/04/17:12:45:24!0!',
        '!!FiveM_ChromeBrowser!2025/04/17:12:45:33!0!', '!!FiveM_ROSLauncher!2025/04/17:11:47:41!0!',
        '!!FiveM_ROSService!2025/04/17:12:45:24!0!', '!!FiveM_b3095_GTAProcess.exe!2025/04/17:12:45:23!0!',
        '!!CitizenFX.exe.new!2025/04/17:12:45:27!5008bd!', '!!CitizenFX.exe.new!2025/04/17:11:48:08!504293!'
    ]
    dps_regex = r'!!([^!]+)!(\d{4}/\d{2}/\d{2}:\d{2}:\d{2}:\d{2})!([0-9a-f]+|0)!'
    flagged_entries = []
    output_file = 'C:\\SS\\dps_strings.txt'

    try:
        tool_path = download_xxstrings()
        if not tool_path:
            return []

        pid = get_dps_pid()
        if not pid:
            print(f"{Fore.YELLOW}Could not get DPS process PID. Is the DPS service running? Skipping.{Style.RESET_ALL}")
            return []

        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        cmd = [tool_path, '-p', str(pid)]

        with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True, check=False)

        if result.returncode != 0:
            print(f'{Fore.RED}[!] Error running strings command on DPS (PID: {pid}): {result.stderr}{Style.RESET_ALL}')
            return []

        if not os.path.exists(output_file):
            print(f'{Fore.YELLOW}Output file {output_file} not found after running strings.{Style.RESET_ALL}')
            return []

        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            matches = re.findall(dps_regex, content, re.MULTILINE)
            for match in matches:
                if len(match) >= 3:
                    filename = match[0]
                    full_match_string = f'!!{filename}!{match[1]}!{match[2]}!'

                    if filename.lower().endswith('.exe'):
                        continue
                    if full_match_string in dps_whitelist:
                        continue

                    flagged_entries.append({
                        'Bypass Detection': 'Modified Extension (DPS Memory)',
                        'Detection': filename,
                        'Notes': 'This file has a possible renamed extension in DPS memory, check this out manually!'
                    })
    except Exception as e:
        print(f'{Fore.RED}Error analyzing DPS strings for renamed extensions: {e}{Style.RESET_ALL}')
    finally:
        delete_file(output_file)
    return flagged_entries

def execution_off_drive():
    """Checks for files executed from drives other than C: by analyzing EventLog service memory."""
    print(f'{Fore.LIGHTMAGENTA_EX}{Style.BRIGHT}Checking for executed files off other drives..{Style.RESET_ALL}')
    eventlog_regex = r'\b(?!C:)[A-Z]:\\[^\\/:*?"<>|\r\n]+\.\w+\b'
    flagged_entries = []
    output_file = 'C:\\SS\\eventlog_strings.txt'

    try:
        tool_path = download_xxstrings()
        if not tool_path:
            return []

        pid = get_eventlog_pid()
        if not pid:
            print(f"{Fore.YELLOW}Could not get EventLog process PID. Is the EventLog service running? Skipping.{Style.RESET_ALL}")
            return []

        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        cmd = [tool_path, '-p', str(pid)]

        with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True, check=False)

        if result.returncode != 0:
            print(f'{Fore.RED}[!] Error running strings command on EventLog (PID: {pid}): {result.stderr}{Style.RESET_ALL}')
            return []

        if not os.path.exists(output_file):
            print(f'{Fore.YELLOW}Output file {output_file} not found after running strings.{Style.RESET_ALL}')
            return []

        unique_files = set()
        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            matches = re.findall(eventlog_regex, content, re.MULTILINE)
            for filename_match in matches:
                if filename_match not in unique_files:
                    unique_files.add(filename_match)
                    flagged_entries.append({
                        'Bypass Detection': 'File Execution from Non-C: Drive (EventLog Memory)',
                        'Detection': filename_match,
                        'Notes': 'This file was executed from another drive and not the C:\\, worth investigating'
                    })
    except Exception as e:
        print(f'{Fore.RED}Error analyzing EventLog strings for off-drive executions: {e}{Style.RESET_ALL}')
    finally:
        delete_file(output_file)
    return flagged_entries

def bam_unicode():
    """Analyzes BAM registry for Unicode characters in executable paths, indicating obfuscation."""
    print(f'{Fore.CYAN}{Style.BRIGHT}Analyzing Registry for Unicode characters...{Style.RESET_ALL}')
    bam_key_path = 'SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings'
    flagged_entries = []
    try:
        with winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE) as hklm:
            with winreg.OpenKey(hklm, bam_key_path) as bam_key:
                subkey_count = winreg.QueryInfoKey(bam_key)[0]
                sid_entry_counts = {}

                for i in range(subkey_count):
                    sid = winreg.EnumKey(bam_key, i)
                    with winreg.OpenKey(bam_key, sid) as sid_key:
                        value_count = winreg.QueryInfoKey(sid_key)[1]
                        sid_entry_counts[sid] = value_count

                if not sid_entry_counts:
                    print(f'{Fore.YELLOW}No SIDs found in BAM registry.{Style.RESET_ALL}')
                    return []

                most_active_sid = max(sid_entry_counts, key=sid_entry_counts.get)
                print(f"Analyzing BAM entries for SID: {most_active_sid} (Most Active){Style.RESET_ALL}")

                with winreg.OpenKey(bam_key, most_active_sid) as sid_key:
                    for j in range(sid_entry_counts[most_active_sid]):
                        try:
                            name, data, value_type = winreg.EnumValue(sid_key, j)
                            if not isinstance(name, str) or not name:
                                continue

                            if has_unicode(name):
                                unicode_chars = find_unicode(name)
                                flagged_entries.append({
                                    'Bypass Detection': 'BAM Unicode Obfuscation',
                                    'Detection': name,
                                    'Notes': f"Unicode characters found: {', '.join(unicode_chars)}"
                                })
                        except OSError as e:
                            print(f"{Fore.YELLOW}Warning: Error enumerating BAM value at index {j} for SID {most_active_sid}: {e}{Style.RESET_ALL}")
                            continue
                        except Exception as e:
                            print(f'{Fore.RED}Error processing BAM entry: {e}{Style.RESET_ALL}')
                            continue
    except FileNotFoundError:
        print(f'{Fore.YELLOW}BAM registry key not found: {bam_key_path}. Skipping BAM Unicode check.{Style.RESET_ALL}')
    except PermissionError:
        print(f'{Fore.RED}Access denied to BAM registry. Please run the script as Administrator.{Style.RESET_ALL}')
    except Exception as e:
        print(f'{Fore.RED}An unexpected error occurred during BAM analysis: {e}{Style.RESET_ALL}')
    return flagged_entries

# ---
# Main Execution Logic
# ---

def main():
    """Main function to run all bypass detection checks and output results to CSV."""
    print(f'{Fore.BLUE}{Style.BRIGHT}Starting Bypass Detection Scan...{Style.RESET_ALL}\n')
    all_detections = []

    all_detections.extend(analyze_evtx())
    all_detections.extend(dll_usage())
    all_detections.extend(anydesk_xfers())
    all_detections.extend(read_only())
    all_detections.extend(prefetch_deletion())
    all_detections.extend(file_replacements())
    all_detections.extend(detect_modified_files())
    all_detections.extend(modified_filess())
    all_detections.extend(ghost_deletion())
    all_detections.extend(analyze_pf())
    all_detections.extend(renamed_extensions())
    all_detections.extend(execution_off_drive())
    all_detections.extend(bam_unicode())

    if all_detections:
        print(f'\n{Fore.GREEN}{Style.BRIGHT}Detections found. Writing results to {CSV_OUT}...{Style.RESET_ALL}')
        fieldnames = ['Bypass Detection', 'Detection', 'Notes']
        try:
            with open(CSV_OUT, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for row in all_detections:
                    writer.writerow(row)
            print(f'{Fore.GREEN}Scan complete. Results saved to {CSV_OUT}{Style.RESET_ALL}')
        except Exception as e:
            print(f'{Fore.RED}Error writing CSV file: {e}{Style.RESET_ALL}')
    else:
        print(f'\n{Fore.GREEN}{Style.BRIGHT}No bypass detections found.{Style.RESET_ALL}')

if __name__ == '__main__':
    ss_dir = 'C:\\SS'
    mftecmd_dir = os.path.dirname(JOURNAL_CSV)

    try:
        if not os.path.exists(ss_dir):
            os.makedirs(ss_dir)
            print(f"Created directory: {ss_dir}")
        if not os.path.exists(mftecmd_dir):
            os.makedirs(mftecmd_dir)
            print(f"Created directory: {mftecmd_dir}")
    except Exception as e:
        print(f"{Fore.RED}Error creating necessary directories ({ss_dir}, {mftecmd_dir}): {e}. Exiting.{Style.RESET_ALL}")
        sys.exit(1)

    main()