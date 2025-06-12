import csv
import hashlib
import logging
import math
import os
import re
import sys
import pefile
import yara
import time
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import blake3

    def fast_hash_file(file_path, chunk_size=4194304):
        hasher = blake3.blake3()
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
except ImportError:
    # If blake3 is not available, these constants will not be defined globally.
    # They should be defined within the functions that use them or handled differently.
    pass
else:
    # These constants are only defined if blake3 is successfully imported.
    # This might cause issues if blake3 fails to import but these constants are still referenced.
    # It's safer to define them unconditionally or within the scope where they are needed.
    CHUNK_SIZE = 8192
    MAX_FILE_SIZE = 524288000
    MAX_THREADS = min(32, (os.cpu_count() or 4) * 2)

DEFAULT_AMCACHE_DIR = Path('C:\\SS\\Amcache')
DEFAULT_OUTPUT = Path('C:\\path_results.csv')
SRUM_RESOURCE_PATTERN = re.compile('^\\d{14}_SrumECmd_AppResourceUseInfo_Output\\.csv$')
SRUM_TIMELINE_PATTERN = re.compile('^\\d{14}_SrumECmd_AppTimelineProvider_Output\\.csv$')
DEFAULT_SRUM_DIR = Path('C:\\SS\\SrumECmd')

class ScanResult:
    def __init__(self):
        self.file_name = ''
        self.file_path = ''
        self.entropy_section = ''
        self.entropy_value = 0.0
        self.mac_timestamps = ''
        self.yara_matches = ''
        self.amcache_sha1 = ''
        self.current_sha1 = ''
        self.possible_replacement = 'no'
        self.signed_status = 'Unknown'
        self.on_disk = 'off disk'
        self.srum_facetime = '0s'
        self.srum_duration = '0s'

    def to_dict(self) -> Dict[str, str]:
        return {
            'File Name': self.file_name,
            'File Path': self.file_path,
            'Signed Status': self.signed_status,
            'Entropy Value': str(self.entropy_value),
            'Entropy Section': self.entropy_section,
            'MAC Timestamps': self.mac_timestamps,
            'Yara Matches': self.yara_matches,
            'Focus Time': self.srum_facetime,
            'Run duration': self.srum_duration,
            'Possible Replacement': self.possible_replacement,
            'On/Off Disk': self.on_disk,
            'Amcache Sha1': self.amcache_sha1,
            'Current Sha1': self.current_sha1
        }

class YaraManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.signed_rules = None
        self.generic_rules = None
        self._load_rules()

    def _load_rules(self):
        sig_rules = """
import "pe"

rule SignedFile {
    meta:
        rule_name = "Signed"
    condition:
        pe.is_signed
}

rule UnsignedFile {
    meta:
        rule_name = "Unsigned"
    condition:
        not pe.is_signed
}
"""
        generic_rules = """
import "pe"
import "math"

rule generic1
{
    meta:
        rule_name = "FiveM Window Detection"

    strings:
        $x1 = "Waiting FiveM window.."
        $x2 = "FiveM_GTAProcess.exe"

    condition:
        $x1 and $x2
}

rule generic2
{
    meta:
        rule_name = "Keyauth"

    strings:
        $x1 = "KeyAuthApp" nocase
        $x2 = "keyauth" nocase

    condition:
        $x1 or $x2
}

rule generic3 {
    meta:
        rule_name = "Generic Cheat [A]"

    strings:
        $s1 = "Aimbot" ascii nocase fullword
        $s2 = "SilentAim" ascii nocase fullword
        $s3 = "WriteProcessMemory" ascii nocase fullword
        $s4 = "ReadProcessMemory" ascii nocase fullword
        $s5 = "LookupPrivilegeValueW" ascii nocase fullword
    condition:
        4 of ($s*)
}

rule generic4
{
    meta:
        rule_name = "Generic Cheat [B]"

    condition:
        pe.is_pe and
        for any section in pe.sections : (math.entropy(section.raw_data_offset, section.raw_data_size) > 7.4) and
        pe.imports("KERNEL32.dll", "IsDebuggerPresent") and
        pe.imports("KERNEL32.dll", "WriteProcessMemory") and
        (
            pe.imports("d3d9.dll", "Direct3DCreate9") or
            pe.imports("d3d11.dll", "D3D11CreateDeviceAndSwapChain") or
            pe.imports("d3d11.dll", "D3D11CreateDevice") or
            pe.imports("D3DCOMPILER_43.dll", "D3DCompile") or
            pe.imports("dd3dx11_43.dll", "D3DX11CreateShaderResourceViewFromMemory") or
            pe.imports("d3dx9_43.dll", "D3DXMatrixTranspose")
        )
}

rule generic5
{
    meta:
        rule_name = "Generic Skript Loader"

    strings:
        $x1 = "json.exception" nocase

    condition:
        pe.is_pe and
        not pe.is_signed and
        $x1 and
        pe.imports("KERNEL32.dll", "LCMapStringW") and
        pe.imports("d3d11.dll", "D3D11CreateDeviceAndSwapChain") and
        pe.imports("ADVAPI32.dll", "RegDeleteValueW") and
        pe.imports("KERNEL32.dll", "ReadConsoleW") and
        filesize > 700KB and
        filesize < 5000KB
}

rule generic6
{
    meta:
        rule_name = "Generic Cheat [C]"

    condition:
        pe.is_pe and
        not pe.is_signed and
        filesize > 2000KB and filesize < 15000KB and

        for any section in pe.sections : (
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.5
        ) and

        (
            (
                uint8(pe.imports("KERNEL32.dll", "WriteProcessMemory")) +
                uint8(pe.imports("ADVAPI32.dll", "CloseHandle"))
            ) >= 1
        ) and

        (
            (
                uint8(pe.imports("ADVAPI32.dll", "RegDeleteKeyA")) +
                uint8(pe.imports("ADVAPI32.dll", "RegDeleteKeyW")) +
                uint8(pe.imports("ADVAPI32.dll", "RegDeleteValueA")) +
                uint8(pe.imports("ADVAPI32.dll", "RegDeleteValueW"))
            ) >= 3
        )
}

rule generic7 {
    meta:
        rule_name = "Generic Suspicious File"

    strings:
        $api1 = "GetModuleHandleA"
        $api2 = "GetWindowLongW"
        $api3 = "VirtualProtect"
        $api4 = "CreateRemoteThread"
        $packer_marker1 = "UPX" nocase
        $packer_marker2 = "MPRESS" nocase
        $packer_marker3 = "ASPack" nocase

    condition:
        filesize > 1024KB and filesize < 30MB and
        (
            for any i in (0..pe.number_of_sections - 1): (
                pe.sections[i].name == ".themida" or
                pe.sections[i].name == ".vmp1" or
                pe.sections[i].name == "UPX1"
            )
        ) and
        (
            $api1 or $api2 or $api3 or $api4 or $packer_marker1 or $packer_marker2 or $packer_marker3
        ) and
        pe.is_pe and
        math.entropy(0, filesize) >= 7.5
}

rule generic8
{
    meta:
        rule_name = "Generic Eulen Loader"

    strings:
        $x1 = "NtQuerySystemInformation" nocase

    condition:
        pe.is_pe and
        not pe.is_signed and
        for any section in pe.sections : (math.entropy(section.raw_data_offset, section.raw_data_size) > 7.7) and
        $x1 and
        pe.imports("SHLWAPI.dll", "PathRemoveFileSpecW") and
        pe.imports("d3d11.dll", "D3D11CreateDeviceAndSwapChain") and
        pe.imports("ADVAPI32.dll", "RegEnumKeyExW") and
        pe.imports("ole32.dll", "RevokeDragDrop") and
        filesize > 19000KB and
        filesize < 40000KB
}

rule generic9 {
    meta:
        rule_name = "Generic Manual Mapping Injector"

    condition:
        pe.is_pe and
        not pe.is_signed and
        filesize > 500KB and filesize < 10000KB and
        for any section in pe.sections : (
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.3
        ) and
        pe.imports("ntdll.dll", "NtQueryInformationProcess") and
        pe.imports("ntdll.dll", "NtUnmapViewOfSection") and
        pe.imports("ntdll.dll", "NtSetInformationThread") and
        pe.imports("KERNEL32.dll", "VirtualAllocEx") and
        pe.imports("KERNEL32.dll", "WriteProcessMemory") and
        pe.imports("KERNEL32.dll", "CreateRemoteThread")
}

rule generic10 {
    meta:
        rule_name = "Generic Process Hollowing"

    condition:
        pe.is_pe and
        not pe.is_signed and
        filesize > 1000KB and filesize < 15000KB and
        pe.imports("ntdll.dll", "ZwUnmapViewOfSection") and
        pe.imports("ntdll.dll", "NtMapViewOfSection") and
        pe.imports("ntdll.dll", "NtCreateSection") and
        pe.imports("KERNEL32.dll", "WriteProcessMemory") and
        pe.imports("KERNEL32.dll", "ResumeThread") and
        pe.imports("KERNEL32.dll", "CreateProcessInternalW")
}

rule generic11 {
    meta:
        rule_name = "Generic Priv Escalation Tool"

    condition:
        pe.is_pe and
        not pe.is_signed and
        filesize < 7000KB and
        pe.imports("ADVAPI32.dll", "OpenProcessToken") and
        pe.imports("ADVAPI32.dll", "LookupPrivilegeValueW") and
        pe.imports("ADVAPI32.dll", "AdjustTokenPrivileges") and
        pe.imports("KERNEL32.dll", "GetCurrentProcess") and
        pe.imports("KERNEL32.dll", "DuplicateHandle")
}

rule generic12 {
    meta:
        rule_name = "Generic Reflective Loader Behavior"

    condition:
        pe.is_pe and
        not pe.is_signed and
        pe.imports("KERNEL32.dll", "VirtualAlloc") and
        pe.imports("KERNEL32.dll", "VirtualProtect") and
        pe.imports("KERNEL32.dll", "CreateThread") and
        pe.imports("KERNEL32.dll", "WaitForSingleObject") and
        pe.imports("KERNEL32.dll", "GetProcAddress") and
        pe.imports("KERNEL32.dll", "LoadLibraryA") and
        filesize > 200KB and filesize < 10000KB
}

rule generic13 {
    meta:
        rule_name = "Generic Registry Wiper"

    condition:
        pe.is_pe and
        not pe.is_signed and
        filesize > 800KB and
        pe.imports("ADVAPI32.dll", "RegDeleteKeyW") and
        pe.imports("ADVAPI32.dll", "RegDeleteValueA") and
        pe.imports("ADVAPI32.dll", "RegEnumKeyExW") and
        pe.imports("ADVAPI32.dll", "RegOpenKeyExW")
}

rule generic14 {
    meta:
        rule_name = "Generic DirectX Overlay Injector (Anti-Overlay Bypass)"

    condition:
        pe.is_pe and
        not pe.is_signed and
        filesize > 1000KB and filesize < 15000KB and
        (
            pe.imports("d3d11.dll", "D3D11CreateDeviceAndSwapChain") or
            pe.imports("d3d9.dll", "Direct3DCreate9") or
            pe.imports("dxgi.dll", "CreateDXGIFactory")
        ) and
        pe.imports("KERNEL32.dll", "VirtualProtect") and
        pe.imports("KERNEL32.dll", "GetProcAddress") and
        pe.imports("USER32.dll", "SetWindowsHookExA") and
        pe.imports("USER32.dll", "GetWindowThreadProcessId")
}

rule fivem_external_cheat_1
{
    meta:
        rule_name = "Generic memory Injection"

    condition:
        pe.is_pe and
        not pe.is_signed and
        pe.imports("KERNEL32.dll", "WriteProcessMemory") and
        pe.imports("KERNEL32.dll", "OpenProcess") and
        pe.imports("KERNEL32.dll", "CreateToolhelp32Snapshot") and
        pe.imports("KERNEL32.dll", "Module32First") and
        pe.imports("KERNEL32.dll", "Module32Next") and
        pe.imports("KERNEL32.dll", "CloseHandle")
}

rule fivem_external_cheat_2
{
    meta:
        rule_name = "Generic Overlay Engine"

    condition:
        pe.is_pe and
        not pe.is_signed and
        pe.imports("user32.dll", "FindWindowA") and
        pe.imports("user32.dll", "GetDC") and
        pe.imports("gdi32.dll", "LineTo") and
        pe.imports("gdi32.dll", "MoveToEx") and
        pe.imports("gdi32.dll", "CreatePen") and
        pe.imports("gdi32.dll", "SelectObject")
}

rule fivem_external_cheat_3
{
    meta:
        rule_name = "Generic Input Simulator"

    condition:
        pe.is_pe and
        pe.imports("user32.dll", "SendInput") and
        pe.imports("user32.dll", "mouse_event") and
        pe.imports("user32.dll", "keybd_event") and
        pe.imports("user32.dll", "SetCursorPos")
}

rule fivem_internal_injector_1
{
    meta:
        rule_name = "Generic DLL Injector"

    condition:
        pe.is_pe and
        not pe.is_signed and
        pe.imports("KERNEL32.dll", "VirtualAllocEx") and
        pe.imports("KERNEL32.dll", "CreateRemoteThread") and
        pe.imports("KERNEL32.dll", "WriteProcessMemory") and
        pe.imports("KERNEL32.dll", "GetProcAddress") and
        pe.imports("KERNEL32.dll", "LoadLibraryA")
}

rule fivem_internal_injector_2
{
    meta:
        rule_name = "Generic Manual Mapper"

    condition:
        pe.is_pe and
        not pe.is_signed and
        pe.imports("ntdll.dll", "NtUnmapViewOfSection") and
        pe.imports("ntdll.dll", "NtQueryInformationProcess") and
        pe.imports("KERNEL32.dll", "VirtualAllocEx") and
        pe.imports("KERNEL32.dll", "WriteProcessMemory") and
        pe.imports("KERNEL32.dll", "CreateRemoteThread")
}

rule fivem_external_loader
{
    meta:
        rule_name = "Generic Registry & Console"

    condition:
        pe.is_pe and
        not pe.is_signed and
        pe.imports("ADVAPI32.dll", "RegSetValueExW") and
        pe.imports("ADVAPI32.dll", "RegOpenKeyExW") and
        pe.imports("KERNEL32.dll", "FreeConsole") and
        pe.imports("KERNEL32.dll", "AllocConsole")
}

rule fivem_internal_hooking
{
    meta:
        rule_name = "Generic Function Hooking"

    condition:
        pe.is_pe and
        not pe.is_signed and
        pe.imports("KERNEL32.dll", "VirtualProtect") and
        pe.imports("KERNEL32.dll", "FlushInstructionCache") and
        pe.imports("KERNEL32.dll", "GetProcAddress") and
        pe.imports("KERNEL32.dll", "LoadLibraryA")
}

rule fivem_internal_sandbox_evasion
{
    meta:
        rule_name = "Generic Sandbox Evasion"

    condition:
        pe.is_pe and
        not pe.is_signed and
        pe.imports("ntdll.dll", "NtQueryInformationProcess") and
        pe.imports("KERNEL32.dll", "IsDebuggerPresent") and
        pe.imports("KERNEL32.dll", "CheckRemoteDebuggerPresent")
}

rule fivem_internal_dx_overlay
{
    meta:
        rule_name = "Generic DX Overlay"

    condition:
        pe.is_pe and
        not pe.is_signed and
        (
            pe.imports("d3d11.dll", "D3D11CreateDeviceAndSwapChain") or
            pe.imports("d3d9.dll", "Direct3DCreate9")
        ) and
        pe.imports("user32.dll", "GetForegroundWindow") and
        pe.imports("KERNEL32.dll", "CreateThread")
}

rule memory_scanner_toolkit
{
    meta:
        rule_name = "Generic Cheat [D]"

    condition:
        pe.is_pe and
        not pe.is_signed and
        filesize > 1500KB and

        (
            (
                uint8(pe.imports("KERNEL32.dll", "ReadProcessMemory")) +
                uint8(pe.imports("KERNEL32.dll", "WriteProcessMemory")) +
                uint8(pe.imports("KERNEL32.dll", "VirtualQueryEx")) +
                uint8(pe.imports("KERNEL32.dll", "VirtualProtectEx")) +
                uint8(pe.imports("ntdll.dll", "NtReadVirtualMemory"))
            ) >= 3
        ) and

        (
            (
                uint8(pe.imports("KERNEL32.dll", "OpenProcess")) +
                uint8(pe.imports("KERNEL32.dll", "GetCurrentProcessId")) +
                uint8(pe.imports("ntdll.dll", "NtOpenProcess")) +
                uint8(pe.imports("PSAPI.dll", "EnumProcesses"))
            ) >= 2
        )
}

rule genericbypassa
{
    meta:
        rule_name = "Generic Bypass [A]"

    condition:

        pe.is_pe and
        filesize < 8MB and

        for any section in pe.sections : (
            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.6
        ) and

        (
            (
                uint8(pe.imports("KERNEL32.dll", "DeleteFileW")) +
                uint8(pe.imports("ADVAPI32.dll", "RegDeleteValueW")) +
                uint8(pe.imports("KERNEL32.dll", "SetFileAttributesW")) +
                uint8(pe.imports("KERNEL32.dll", "WriteFile")) +
                uint8(pe.imports("KERNEL32.dll", "SetEndOfFile"))
            ) >= 4
        ) and

        (
            (
                uint8(pe.imports("KERNEL32.dll", "GetTempPathW")) +
                uint8(pe.imports("KERNEL32.dll", "GetWindowsDirectoryW")) +
                uint8(pe.imports("KERNEL32.dll", "GetSystemDirectoryW")) +
                uint8(pe.imports("SHLWAPI.dll", "PathFileExistsW"))
            ) >= 3
        )
}
"""
        try:
            print('Compiling YARA rules...')
            self.signed_rules = yara.compile(source=sig_rules)
            self.generic_rules = yara.compile(source=generic_rules)
            print('Successfully compiled YARA rules')
        except Exception as e:
            print(f'Failed to compile YARA rules: {e}')

    def scan_file(self, file_path: Path) -> Tuple[List[yara.Match], List[yara.Match]]:
        signed_matches = []
        generic_matches = []
        try:
            if not self.signed_rules or not self.generic_rules:
                print('Warning: YARA rules not loaded, skipping scan')
                return (signed_matches, generic_matches)
            
            # YARA expects a string path
            if self.signed_rules:
                signed_matches = self.signed_rules.match(str(file_path))
            if self.generic_rules:
                generic_matches = self.generic_rules.match(str(file_path))
        except yara.Error as e:
            self.logger.error(f'YARA scan failed for {file_path}: {e}')
        except Exception as e:
            self.logger.error(f'An unexpected error occurred during YARA scan for {file_path}: {e}')
        return (signed_matches, generic_matches)

def extract_exe_name_from_srum_path(exe_info: str) -> str:
    """Extracts the executable name from a SRUM ExeInfo string."""
    if not exe_info or exe_info.strip() == '':
        return ''
    
    exe_info = exe_info.strip()
    
    # Handle paths like \Device\HarddiskVolumeX\...\program.exe
    if exe_info.startswith('\\Device\\'):
        return Path(exe_info).name.lower()
    
    # Handle paths with '!' delimiter like '!!C:\Path\To\program.exe!...'
    if '!' in exe_info:
        parts = exe_info.split('!')
        for part in parts:
            if part.endswith('.exe'):
                return part.lower()
    
    # Fallback to just the filename if it's a regular path
    if '\\' in exe_info:
        return Path(exe_info).name.lower()
    
    return exe_info.lower()

def format_nanoseconds(nanoseconds: int) -> str:
    """Converts nanoseconds to a human-readable duration string."""
    if nanoseconds == 0:
        return '0s'
    seconds = int(nanoseconds / 1_000_000_000)
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    parts = []
    if hours > 0:
        parts.append(f'{hours}h')
    if minutes > 0:
        parts.append(f'{minutes}m')
    if secs > 0 or not parts: # Include seconds if no hours/minutes, or if it's 0 seconds
        parts.append(f'{secs}s')
    return ' '.join(parts)

def format_milliseconds(milliseconds: int) -> str:
    """Convert milliseconds to readable format (e.g., 1h 20m 30s)."""
    if milliseconds == 0:
        return '0s'
    seconds = int(milliseconds / 1000)
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    parts = []
    if hours > 0:
        parts.append(f'{hours}h')
    if minutes > 0:
        parts.append(f'{minutes}m')
    if secs > 0 or not parts: # Include seconds if no hours/minutes, or if it's 0 seconds
        parts.append(f'{secs}s')
    return ' '.join(parts)

def setup_logging() -> logging.Logger:
    """Sets up basic logging configuration."""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler()])
    return logging.getLogger(__name__)

def get_sha1(file_path: Path) -> Optional[str]:
    """Calculates the SHA1 hash of a given file."""
    sha1 = hashlib.sha1()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha1.update(chunk)
        return sha1.hexdigest().lower()
    except Exception as e:
        logging.error(f'[X] Failed to calculate SHA1 for {file_path}: {e}')
        return None

def calc_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a given byte string."""
    if not data:
        return 0.0
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    entropy = 0.0
    data_len = len(data)
    for count in byte_counts.values():
        prob = count / data_len
        entropy -= prob * math.log2(prob)
    return entropy

def find_highest_entropy(pe: pefile.PE) -> Tuple[str, float]:
    """Finds the section with the highest entropy in a PE file."""
    max_entropy = 0.0
    max_section = ''
    for section in pe.sections:
        try:
            data = section.get_data()
            entropy = calc_entropy(data)
            if entropy > max_entropy:
                max_entropy = entropy
                section_name = section.Name.decode('utf-8', errors='ignore')
                max_section = section_name.rstrip('\x00')
        except Exception as e:
            logging.debug(f"Error calculating entropy for section {section.Name}: {e}")
            continue # Continue to the next section
    return (max_section, max_entropy)

def file_timestamps(path: Path) -> str:
    """Retrieves and formats MAC (Modified, Accessed, Created) timestamps of a file."""
    try:
        stat = path.stat()
        return f'M: {time.ctime(stat.st_mtime)}; A: {time.ctime(stat.st_atime)}; C: {time.ctime(stat.st_ctime)}'
    except Exception as e:
        logging.warning(f"Could not get timestamps for {path}: {e}")
        return ''

def ask_yes_no(prompt: str) -> bool:
    """Prompts the user for a yes/no answer."""
    while True:
        ans = input(f'{prompt} (yes/no): ').strip().lower()
        if ans in ['yes', 'no', 'y', 'n']:
            return ans in ('yes', 'y')
        print('Bruh, just say yes or no...')

def load_paths(file_path: str) -> List[Path]:
    """Loads a list of file paths from a text file."""
    paths = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                p = line.strip()
                if p:
                    paths.append(Path(p))
        return paths
    except Exception as e:
        logging.error(f'[X] Error reading text file {file_path}: {e}')
        return []

def find_srum_file(pattern: re.Pattern, srum_dir: Path) -> Optional[Path]:
    """Find SRUM file matching the given pattern in the SRUM directory."""
    try:
        if srum_dir.exists() and srum_dir.is_dir():
            for file_path in srum_dir.iterdir():
                if pattern.match(file_path.name):
                    return file_path
        return None
    except Exception as e:
        logging.error(f'Error searching for SRUM file in {srum_dir}: {e}')
        return None

class PathScanner:
    def __init__(self):
        self.logger = setup_logging()
        self.yara = YaraManager()
        # Ensure CHUNK_SIZE and MAX_THREADS are defined if blake3 fails to import
        # For simplicity, defining them unconditionally here.
        global CHUNK_SIZE, MAX_FILE_SIZE, MAX_THREADS
        if 'CHUNK_SIZE' not in globals():
            CHUNK_SIZE = 8192
            MAX_FILE_SIZE = 524288000
            MAX_THREADS = min(32, (os.cpu_count() or 4) * 2)

        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_THREADS)
        self.total_files = 0
        self.scanned_files = 0
        self.facetime_data: Dict[str, int] = {}
        self.duration_data: Dict[str, int] = {}
        if sys.platform == 'win32':
            try:
                import psutil
                p = psutil.Process(os.getpid())
                p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            except Exception as e:
                self.logger.warning(f"Could not set process priority: {e}")

    def find_amcache_csv(self) -> Optional[Path]:
        """Finds the latest Amcache UnassociatedFileEntries CSV file."""
        pattern = re.compile('^\\d+_Amcache_UnassociatedFileEntries\\.csv$')
        latest_file = None
        latest_timestamp = 0
        try:
            if DEFAULT_AMCACHE_DIR.exists() and DEFAULT_AMCACHE_DIR.is_dir():
                for file_path in DEFAULT_AMCACHE_DIR.iterdir():
                    if pattern.match(file_path.name):
                        # Extract timestamp from filename (e.g., 20240101120000_Amcache...)
                        timestamp_str = file_path.name.split('_')[0]
                        try:
                            timestamp = int(timestamp_str)
                            if timestamp > latest_timestamp:
                                latest_timestamp = timestamp
                                latest_file = file_path
                        except ValueError:
                            continue
            return latest_file
        except Exception as e:
            self.logger.error(f'Error searching for Amcache CSV: {e}')
            return None

    def load_amcache_data(self, csv_path: Path) -> Tuple[List[Path], Dict[str, str]]:
        """Loads Amcache data, returning a list of paths and a SHA1 map."""
        paths = []
        sha1_map = {}
        try:
            with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    path_str = row.get('FullPath', '').strip()
                    sha1 = row.get('SHA1', '').strip()
                    if path_str:
                        p = Path(path_str)
                        paths.append(p)
                        if sha1:
                            sha1_map[path_str.lower()] = sha1.lower()
            return (paths, sha1_map)
        except Exception as e:
            self.logger.error(f'Error reading Amcache CSV {csv_path}: {e}')
            return ([], {})

    def load_srum_data(self) -> Tuple[Dict[str, int], Dict[str, int]]:
        """Loads SRUM data for facetime and duration."""
        facetime_data = {}
        duration_data = {}
        try:
            resource_file = find_srum_file(SRUM_RESOURCE_PATTERN, DEFAULT_SRUM_DIR)
            if resource_file:
                try:
                    with open(resource_file, 'r', encoding='utf-8', errors='ignore') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            exe_name = extract_exe_name_from_srum_path(row.get('ExeInfo', ''))
                            if exe_name:
                                # Initialize if not present
                                if exe_name not in facetime_data:
                                    facetime_data[exe_name] = 0
                                facetime_str = row.get('FaceTime', '0')
                                try:
                                    # Convert to int, handling potential float strings
                                    facetime_value = int(float(facetime_str)) if facetime_str and facetime_str.strip() else 0
                                    facetime_data[exe_name] += facetime_value
                                except (ValueError, TypeError):
                                    self.logger.warning(f"Invalid FaceTime value for {exe_name}: {facetime_str}")
                                    pass
                except Exception as e:
                    self.logger.error(f'Error reading SRUM Resource file {resource_file}: {e}')
            else:
                self.logger.warning('[-] SRUM Resource file not found in %s', DEFAULT_SRUM_DIR)

            timeline_file = find_srum_file(SRUM_TIMELINE_PATTERN, DEFAULT_SRUM_DIR)
            if timeline_file:
                try:
                    with open(timeline_file, 'r', encoding='utf-8', errors='ignore') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            exe_name = extract_exe_name_from_srum_path(row.get('ExeInfo', ''))
                            if exe_name:
                                # Initialize if not present
                                if exe_name not in duration_data:
                                    duration_data[exe_name] = 0
                                duration_str = row.get('DurationMs', '0')
                                try:
                                    # Convert to int, handling potential float strings
                                    duration_value = int(float(duration_str)) if duration_str and duration_str.strip() else 0
                                    duration_data[exe_name] += duration_value
                                except (ValueError, TypeError):
                                    self.logger.warning(f"Invalid DurationMs value for {exe_name}: {duration_str}")
                                    pass
                except Exception as e:
                    self.logger.error(f'Error reading SRUM Timeline file {timeline_file}: {e}')
            else:
                self.logger.warning('[-] SRUM Timeline file not found in %s', DEFAULT_SRUM_DIR)
        except Exception as e:
            self.logger.error(f'[X] Error loading SRUM data: {e}')
        return (facetime_data, duration_data)

    def is_pe_file(self, file_path: Path) -> bool:
        """Check if a file is a PE by reading its magic bytes."""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(2)
                return magic == b'MZ'
        except Exception as e:
            self.logger.debug(f"Could not read magic bytes for {file_path}: {e}")
            return False

    def scan_file(self, file_path: Path, sha1_map: Dict[str, str]) -> ScanResult:
        """Performs a comprehensive scan of a single file."""
        # start_time = time.time() # Not used in current logic
        result = ScanResult()
        result.file_name = file_path.name
        result.file_path = str(file_path)
        exe_name = file_path.name.lower()

        # Load SRUM data if available
        if exe_name in self.facetime_data:
            result.srum_facetime = format_nanoseconds(self.facetime_data[exe_name])
        if exe_name in self.duration_data:
            result.srum_duration = format_milliseconds(self.duration_data[exe_name])

        # Check if file exists on disk
        if file_path.exists() and file_path.is_file():
            result.on_disk = 'On Disk'
        else:
            result.on_disk = 'Off Disk'
            return result # If file is off disk, no further scanning is possible

        try:
            file_size = file_path.stat().st_size
            if file_size > MAX_FILE_SIZE:
                result.current_sha1 = 'SKIPPED-LARGE-FILE' # Indicate skipped hashing for large files
                return result
        except Exception as e:
            self.logger.error(f"Error getting file size for {file_path}: {e}")
            return result # Can't proceed if file size can't be determined

        # Calculate current SHA1 hash (using blake3 if available, otherwise fallback)
        curr_hash = None
        if 'fast_hash_file' in globals() and not blake3: # Check if blake3 import failed
             logging.warning("blake3 not available, falling back to hashlib.sha1 for hashing.")
             curr_hash = get_sha1(file_path)
        elif 'fast_hash_file' in globals(): # blake3 is available
            try:
                curr_hash = fast_hash_file(file_path)
            except Exception as e:
                self.logger.error(f"Error using blake3 for {file_path}: {e}. Falling back to SHA1.")
                curr_hash = get_sha1(file_path)
        else: # blake3 module not imported at all, use hashlib.sha1
            curr_hash = get_sha1(file_path)

        result.current_sha1 = curr_hash if curr_hash else ''

        # Compare with Amcache SHA1
        amcache_sha1 = sha1_map.get(str(file_path).lower(), '')
        result.amcache_sha1 = amcache_sha1
        if curr_hash and amcache_sha1 and (curr_hash != amcache_sha1):
            result.possible_replacement = 'yes'

        # PE file analysis (entropy, signed status)
        if self.is_pe_file(file_path) and file_size <= MAX_FILE_SIZE: # Re-check size for PE parsing
            try:
                pe = pefile.PE(str(file_path), fast_load=True)
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])

                section, entropy = find_highest_entropy(pe)
                result.entropy_section = section
                result.entropy_value = entropy

                # Check signed status from YARA rules
                signed_matches, generic_matches = self.yara.scan_file(file_path)
                
                # Determine signed status from YARA signed rules
                for match in signed_matches:
                    if match.rule == 'SignedFile':
                        result.signed_status = 'Signed'
                        break
                    elif match.rule == 'UnsignedFile':
                        result.signed_status = 'Unsigned'
                        break

                # Collect generic YARA matches
                match_names = []
                for match in generic_matches:
                    # Exclude general signed/unsigned rules if they are returned by generic_rules for some reason
                    if match.rule not in ['SignedFile', 'UnsignedFile']:
                        match_name = match.meta.get('rule_name', match.rule)
                        match_names.append(match_name)
                
                if match_names:
                    result.yara_matches = ';'.join(match_names)

            except pefile.PEFormatError as e:
                self.logger.warning(f"File {file_path} is not a valid PE file or corrupted: {e}")
                result.signed_status = 'Not a PE File'
            except Exception as e:
                self.logger.error(f"Error processing PE file {file_path}: {e}")
        elif not self.is_pe_file(file_path):
            result.signed_status = 'Not a PE File'

        # Get MAC timestamps
        result.mac_timestamps = file_timestamps(file_path)
        
        # self.logger.debug(f"Scanned {file_path} in {time.time() - start_time:.4f} seconds")
        return result

    def scan_paths_threaded(self, paths: List[Path], amcache_sha1_map: Dict[str, str]) -> List[ScanResult]:
        """Scans multiple paths concurrently using a thread pool."""
        self.total_files = len(paths)
        self.scanned_files = 0
        all_results: List[ScanResult] = []

        futures = [self.thread_pool.submit(self.scan_file, p, amcache_sha1_map) for p in paths]

        for future in as_completed(futures):
            self.scanned_files += 1
            try:
                result = future.result()
                all_results.append(result)
                # print(f"Progress: {self.scanned_files}/{self.total_files} files scanned.") # Live progress
            except Exception as e:
                self.logger.error(f"Error during file scan: {e}")
        
        return all_results

def main():
    logger = setup_logging()
    scanner = PathScanner()

    # Load SRUM data first
    logger.info("Loading SRUM data...")
    scanner.facetime_data, scanner.duration_data = scanner.load_srum_data()
    logger.info("SRUM data loaded.")

    # Find and load Amcache data
    amcache_csv_path = scanner.find_amcache_csv()
    amcache_paths: List[Path] = []
    amcache_sha1_map: Dict[str, str] = {}
    if amcache_csv_path:
        logger.info(f"Loading Amcache data from {amcache_csv_path}...")
        amcache_paths, amcache_sha1_map = scanner.load_amcache_data(amcache_csv_path)
        logger.info(f"Loaded {len(amcache_paths)} paths from Amcache.")
    else:
        logger.warning("Amcache CSV not found. Skipping Amcache analysis.")

    # Get paths from user input or default
    target_paths: List[Path] = []
    if len(sys.argv) > 1:
        # If arguments are provided, assume they are file paths or a list file
        input_path = Path(sys.argv[1])
        if input_path.is_file():
            logger.info(f"Loading target paths from {input_path}...")
            target_paths = load_paths(str(input_path))
        elif input_path.is_dir():
            logger.info(f"Scanning all files in directory {input_path} (recursively)...")
            # Collect all files recursively, filter to relevant extensions if needed
            for root, _, files in os.walk(input_path):
                for file in files:
                    full_path = Path(root) / file
                    # Basic filtering for common executables/DLLs
                    if full_path.suffix.lower() in ['.exe', '.dll', '.sys', '.ocx', '.scr']:
                        target_paths.append(full_path)
        else:
            logger.error(f"Invalid input: {input_path} is not a file or directory.")
            sys.exit(1)
    else:
        # If no arguments, use paths from Amcache or prompt for a list
        if amcache_paths:
            logger.info("Using paths from Amcache for scanning. To scan a specific file/directory, provide it as an argument.")
            target_paths = amcache_paths
        else:
            list_file = input("Enter path to a file containing a list of paths to scan: ").strip()
            if list_file:
                target_paths = load_paths(list_file)
            else:
                logger.error("No input paths provided. Exiting.")
                sys.exit(1)

    if not target_paths:
        logger.warning("No files to scan. Exiting.")
        sys.exit(0)

    logger.info(f"Starting scan of {len(target_paths)} files...")
    results = scanner.scan_paths_threaded(target_paths, amcache_sha1_map)
    logger.info("Scan complete. Writing results to CSV.")

    # Write results to CSV
    try:
        with open(DEFAULT_OUTPUT, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ScanResult().to_dict().keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                writer.writerow(result.to_dict())
        logger.info(f"Results saved to {DEFAULT_OUTPUT}")
    except Exception as e:
        logger.error(f"Error writing output CSV: {e}")

if __name__ == '__main__':
    main()