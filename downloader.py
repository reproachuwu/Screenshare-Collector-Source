import os
import sys
import ctypes
import zipfile
import subprocess
import requests
import shutil
import re
import glob
from functools import partial
from time import sleep

def is_admin():
    if ctypes.windll.shell32.IsUserAnAdmin()!= 0:
        return True
    ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, __file__, None, 1)
    sys.exit()

def ssfolder():
    path = 'C:\\SS'
    os.makedirs(path, exist_ok=True)
    print(f'[+] SS folder ready: {path}')
    return path

def download_file(url, dest, retries=3, chunk_size=8192):
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        print(f'[+] Already downloaded: {os.path.basename(dest)}')
        return
    for attempt in range(retries):
        try:
            with session.get(url, stream=True, timeout=20) as r:
                pass  # postinserted
        except Exception as e:
                r.raise_for_status()
                with open(dest, 'wb') as f:
                    shutil.copyfileobj(r.raw, f, length=chunk_size)
                    print(f'[+] Downloaded: {os.path.basename(dest)}')
        else:  # inserted
            break
        print(f'[!] Download error ({os.path.basename(dest)}): {e}')
        if attempt < retries - 1:
            print('[-] Retrying...')
            sleep(2)
        else:  # inserted
            raise
    else:  # inserted
        pass

def tools(tool_name, url, zip_name=None, exe_name=None, commands=None, nested_folder=False, is_exe=False, file_path=None, cleanup=True, base_folder=None, use_glob=False):
    base = base_folder or ssfolder()
    folder = os.path.join(base, tool_name)
    os.makedirs(folder, exist_ok=True)
    dest = os.path.join(folder, file_path or os.path.basename(url))
    print(f'[=] Getting {tool_name}...')
    download_file(url, dest)
    if is_exe:
        print(f'[+] {tool_name} is ready')
        if commands:
            exe_path = dest
            for cmd in commands:
                if use_glob:
                    processed_cmd = []
                    for arg in cmd:
                        if '*' in arg and '.csv' in arg:
                            matches = glob.glob(arg)
                            if matches:
                                processed_cmd.append(matches[0])
                                print(f'[+] Found file: {os.path.basename(matches[0])}')
                            else:  # inserted
                                print(f'[!] No files found matching pattern: {arg}')
                                processed_cmd.append(arg)
                        else:  # inserted
                            processed_cmd.append(arg.format(folder=folder) if '{folder}' in arg else arg)
                    full_cmd = [exe_path] + processed_cmd[1:]
                else:  # inserted
                    full_cmd = [exe_path] + [arg.format(folder=folder) for arg in cmd[1:]]
                result = subprocess.run(full_cmd, cwd=folder, capture_output=True, text=True)
                if result.stdout.strip():
                    print(f'[CMD] {result.stdout.strip()}')
                if result.stderr.strip():
                    print(f'[X] {result.stderr.strip()}')
        if cleanup and tool_name == 'usnhelper':
            os.remove(dest)
            print(f'[X] Removed {os.path.basename(dest)}')
            shutil.rmtree(folder)
            print(f'[X] Removed folder: {folder}')
        print()
    else:  # inserted
        if not is_exe:
            if zip_name:
                print(f'[=] Extracting {zip_name}...')
                with zipfile.ZipFile(dest, 'r') as z:
                    z.extractall(folder)
                exe_dir = os.path.join(folder, os.path.splitext(zip_name)[0]) if nested_folder else folder
                if commands:
                    for cmd in commands:
                        full_cmd = [os.path.join(exe_dir, cmd[0])] + [arg.format(folder=folder) for arg in cmd[1:]]
                        result = subprocess.run(full_cmd, cwd=exe_dir, capture_output=True, text=True)
                        print(f'[CMD] {result.stdout.strip()}')
                        if result.stderr.strip():
                            print(f'[X] {result.stderr.strip()}')
                if cleanup:
                    os.remove(dest)
                    print(f'[X] Removed {zip_name}\n')
is_admin()
session = requests.Session()
amcache = partial(tools, tool_name='Amcache', url='https://download.ericzimmermanstools.com/net9/AmcacheParser.zip', zip_name='AmcacheParser.zip', commands=[['AmcacheParser.exe', '-f', 'C:\\Windows\\appcompat\\Programs\\Amcache.hve', '--csv', '{folder}']])
shimcache = partial(tools, tool_name='ShimCache', url='https://download.ericzimmermanstools.com/AppCompatCacheParser.zip', zip_name='AppCompatCacheParser.zip', commands=[['AppCompatCacheParser.exe', '--csv', '{folder}']])
hxd = partial(tools, tool_name='HxD', url='https://mh-nexus.de/downloads/HxDSetup.zip', zip_name='HxDSetup.zip')
hayabusa = partial(tools, tool_name='HayaBusa', url='https://github.com/Yamato-Security/hayabusa/releases/download/v3.1.1/hayabusa-3.1.1-win-x64.zip', zip_name='hayabusa-3.1.1-win-x64.zip')
everything = partial(tools, tool_name='Everything Tool', url='https://www.voidtools.com/Everything-1.4.1.1026.x64-Setup.exe', is_exe=True)
systeminformer = partial(tools, tool_name='System Informer Canary', url='https://github.com/winsiderss/si-builds/releases/download/3.2.25078.1756/systeminformer-3.2.25078.1756-canary-setup.exe', is_exe=True)
bstrings = partial(tools, tool_name='bstrings', url='https://download.ericzimmermanstools.com/net9/bstrings.zip', zip_name='bstrings.zip')
die = partial(tools, tool_name='Detect It Easy', url='https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win64_portable_3.10_x64.zip', zip_name='die_win64_portable_3.10_x64.zip')
jumplistexplorer = partial(tools, tool_name='JumpListExplorer', url='https://download.ericzimmermanstools.com/net6/JumpListExplorer.zip', zip_name='JumpListExplorer.zip')
mftecmd = partial(tools, tool_name='MFTECmd', url='https://download.ericzimmermanstools.com/MFTECmd.zip', zip_name='MFTECmd.zip', commands=[['MFTECmd.exe', '-f', 'C:\\$Extend\\$UsnJrnl:$J', '-m', 'C:\\$MFT', '--csv', '.']])
usnhelper = partial(tools, tool_name='usnhelper', url='https://raw.githubusercontent.com/txchnology/test/main/usnjrnl_rewind.exe', is_exe=True, use_glob=True, commands=[['usnhelper.exe', '-m', 'C:\\SS\\MFTECmd\\*_MFTECmd_$MFT_Output.csv', '-u', 'C:\\SS\\MFTECmd\\*_MFTECmd_$J_Output.csv', 'C:\\SS\\MFTECmd']])
pecmd = partial(tools, tool_name='PECmd', url='https://download.ericzimmermanstools.com/net9/PECmd.zip', zip_name='PECmd.zip')
registryexplorer = partial(tools, tool_name='RegistryExplorer', url='https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip', zip_name='RegistryExplorer.zip')
srumecmd = partial(tools, tool_name='SrumECmd', url='https://download.ericzimmermanstools.com/net9/SrumECmd.zip', zip_name='SrumECmd.zip', commands=[['SrumECmd.exe', '-f', 'C:\\Windows\\System32\\sru\\SRUDB.dat', '--csv', '{folder}']])
timelineexplorer = partial(tools, tool_name='TimelineExplorer', url='https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip', zip_name='TimelineExplorer.zip')
wxtcmd = partial(tools, tool_name='WxTCmd', url='https://download.ericzimmermanstools.com/net9/WxTCmd.zip', zip_name='WxTCmd.zip', commands=[['WxTCmd.exe', '-f', 'C:\\Users\\%USERNAME%\\AppData\\Local\\ConnectedDevicesPlatform\\d4004aa3b0cb4810\\ActivitiesCache.db', '--csv', '{folder}']])
ramdumpexplorer = partial(tools, tool_name='RamDumpExplorer', url='https://github.com/bacanoicua/RAMDumpExplorer/releases/download/1.0/RAMDumpExplorer.exe', is_exe=True)
usbdeview = partial(tools, tool_name='UsbDeview', url='https://www.nirsoft.net/utils/usbdeview-x64.zip', zip_name='usbdeview-x64.zip')
alternatestreamview = partial(tools, tool_name='AlternateStreamView', url='https://www.nirsoft.net/utils/alternatestreamview-x64.zip', zip_name='alternatestreamview-x64.zip')
winprefetchview = partial(tools, tool_name='WinPrefetchView', url='https://www.nirsoft.net/utils/winprefetchview-x64.zip', zip_name='winprefetchview-x64.zip')
pathsparser = partial(tools, tool_name='PathsParser', url='https://github.com/spokwn/PathsParser/releases/download/v1.0.11/PathsParser.exe', is_exe=True)
prefetchparser = partial(tools, tool_name='PrefetchParser', url='https://github.com/spokwn/prefetch-parser/releases/download/v1.5.4/PrefetchParser.exe', is_exe=True)
processparser = partial(tools, tool_name='ProcessParser', url='https://github.com/spokwn/process-parser/releases/download/v0.5.4/ProcessParser.exe', is_exe=True)
pcasvex = partial(tools, tool_name='PcaSvcExecuted', url='https://github.com/spokwn/pcasvc-executed/releases/download/v0.8.6/PcaSvcExecuted.exe', is_exe=True)
bamparser = partial(tools, tool_name='BAMParser', url='https://github.com/spokwn/BAM-parser/releases/download/v1.2.7/BAMParser.exe', is_exe=True)
journaltrace = partial(tools, tool_name='JournalTrace', url='https://github.com/spokwn/JournalTrace/releases/download/1.2/JournalTrace.exe', is_exe=True)
replaceparser = partial(tools, tool_name='ReplaceParser', url='https://github.com/spokwn/Replaceparser/releases/download/v1.1-recode/ReplaceParser.exe', is_exe=True)
recmd = partial(tools, tool_name='RECmd', url='https://download.ericzimmermanstools.com/net9/RECmd.zip', zip_name='RECmd.zip', nested_folder=True)
velociraptor = partial(tools, tool_name='Velociraptor', url='https://github.com/Velocidex/velociraptor/releases/download/v0.73/velociraptor-v0.73.4-windows-amd64.exe', is_exe=True)
winliveinfo = partial(tools, tool_name='WinLiveInfo', url='https://github.com/kacos2000/Win10LiveInfo/releases/download/v.1.0.23.0/WinLiveInfo.exe', is_exe=True)
exeinfope = partial(tools, tool_name='ExeInfoPe', url='https://cdn.discordapp.com/attachments/1280238836626231379/1280238836814712983/exeinfope.zip?ex=682d7814&is=682c2694&hm=3152a4be175e0a18ea93c84618c21b587d9a4237ec2cb0e519a830690c1cec99&', is_exe=True)

def run():
    for tool in (amcache, shimcache, hxd, hayabusa, everything, systeminformer, bstrings, die, jumplistexplorer, mftecmd, pecmd, usnhelper, registryexplorer, srumecmd, timelineexplorer, wxtcmd, ramdumpexplorer, usbdeview, alternatestreamview, winprefetchview, pathsparser, prefetchparser, processparser, pcasvex, bamparser, journaltrace, replaceparser, recmd, velociraptor, winliveinfo, exeinfope):
        try:
            tool()
        except Exception as e:
            pass  # postinserted
        print(f"[!] Failed to process {tool.keywords['tool_name']}: {e}")
if __name__ == '__main__':
    run()