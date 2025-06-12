
# Source Code leaked by Rep

import os
import time
import requests
import tkinter as tk
from tkinter import messagebox
from pathlib import Path
SS_FOLDER = Path('C:/SS')
EXECUTABLES = {'1': {'name': 'downloader.exe', 'url': 'https://raw.githubusercontent.com/txchnology/test/main/downloader.exe'}, '2': {'name': 'path_scanner.exe', 'url': 'https://raw.githubusercontent.com/txchnology/test/main/path_scanner.exe'}, '3': {'name': 'bypass_checks.exe', 'url': 'https://raw.githubusercontent.com/txchnology/test/main/bypass_checks.exe'}, '4': {'name': 'deletor.exe', 'url': 'https://raw.githubusercontent.com/txchnology/test/main/deletor.exe'}}

def show_user_agreement() -> bool:
    root = tk.Tk()
    root.withdraw()
    message = 'This tool analyzes your system using forensic methods (e.g., SRU, Amcache, Registry, Journal, Process Memory) to detect cheats or bypass tools in games like FiveM, GTAV, Minecraft, and others.\nIt does NOT collect personal data such as passwords, emails, or usernames.\nNetwork activity is required only to download trusted forensic modules, saved in `C:\\SS`.\n\nThis tool cannot be forced to run on any suspects computer by any PC checker or screensharer unless it\'s enforced by the server itself.\n\nBy continuing, you agree to run this program voluntarily.\n\nDo you accept and wish to continue?'
    result = messagebox.askyesno('Technical Unity – User Agreement', message, icon='question')
    root.destroy()
    return result

def show_free_tool_notice():
    root = tk.Tk()
    root.withdraw()
    message = 'This tool is completely free and can be found at:\nhttps://github.com/txvch/Screenshare-Collector\n\nIf you paid for this, you\'ve been scammed.\n\nStay safe and always verify sources.'
    messagebox.showinfo('Notice – Free Tool Information', message, icon='info')
    root.destroy()

def download_dotnet_runtime():
    downloads_folder = Path(os.path.join(os.path.expanduser('~'), 'Downloads'))
    downloads_folder.mkdir(parents=True, exist_ok=True)
    dotnet_urls = {'dotnet_runtime_6.0.36.exe': 'https://builds.dotnet.microsoft.com/dotnet/WindowsDesktop/6.0.36/windowsdesktop-runtime-6.0.36-win-x64.exe', 'dotnet_launcher_9.0.0.exe': 'https://builds.dotnet.microsoft.com/dotnet/Runtime/9.0.5/dotnet-runtime-9.0.5-win-x64.exe'}
    for filename, url in dotnet_urls.items():
        file_path = downloads_folder / filename
        try:
            print(f'Downloading {filename} to Downloads folder...')
            response = requests.get(url, allow_redirects=True)
            response.raise_for_status()
            with open(file_path, 'wb') as f:
                pass  # postinserted
        except Exception as e:
                f.write(response.content)
                print(f'Downloaded: {file_path}')
    else:  # inserted
        print('\n[!] Please run both installers from your Downloads folder:')
        print('- dotnet_runtime_6.0.36.exe')
        print('- dotnet_launcher_9.0.0.exe')
        input('[*] After installation is complete, type \'continue\' and press Enter to proceed: ')
        print(f'Failed to download {filename}: {e}')

def ensure_ss_folder():
    try:
        SS_FOLDER.mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        print(f'Failed to create SS folder: {e}')
        return False
    else:  # inserted
        pass

def download_executable(url: str, filename: str) -> bool:
    try:
        print(f'Downloading {filename}...')
        response = requests.get(url, stream=True)
        response.raise_for_status()
        file_path = SS_FOLDER / filename
        total_size = int(response.headers.get('content-length', 0))
        block_size = 8192
        downloaded = 0
        with open(file_path, 'wb') as f:
            pass  # postinserted
    except Exception as e:
            for data in response.iter_content(block_size):
                downloaded += len(data)
                f.write(data)
                if total_size > 0:
                    percent = downloaded / total_size * 100
                    print(f'\rProgress: {percent:.1f}%', end='')
                print('\nDownload complete!')
                return True
            print(f'Failed to download {filename}: {e}')
            return False

def run_executable(filename: str):
    try:
        exe_path = SS_FOLDER / filename
        if not exe_path.exists():
            print(f'Error: {filename} not found. Please download it first.')
            return False
        print(f'Running {filename}...')
        os.system(f'\"{exe_path}\"')
        return True
    except Exception as e:
        print(f'Error running {filename}: {e}')
        return False
    else:  # inserted
        pass

def print_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print('\n--- Tech\'s Screenshare Tool ---')
    print('[1] Downloader')
    print('[2] Paths Scanner')
    print('[3] Generic Bypass Checks')
    print('[4] Delete All SS Tools')
    print('[5] Exit')

def main():
    if not show_user_agreement():
        print('User agreement not accepted. Exiting...')
        time.sleep(1.3)
        return
    show_free_tool_notice()
    user_dotnet = input('\nDo you want to download the .NET Desktop Runtime (Required for some tools)? (yes/no): ').strip().lower()
    if user_dotnet == 'yes':
        download_dotnet_runtime()
    if not ensure_ss_folder():
        print('Failed to create SS folder. Exiting...')
        time.sleep(2)
        return
    while True:
        print_menu()
        choice = input('\n[>>] Choose an option: ').strip()
        if choice == '6':
            print('Exiting..')
            time.sleep(1.3)
            return
        if choice not in EXECUTABLES:
            print('Invalid option. Try again.')
            continue
        exe_info = EXECUTABLES[choice]
        exe_path = SS_FOLDER / exe_info['name']
        if not exe_path.exists() and (not download_executable(exe_info['url'], exe_info['name'])):
            print('Download failed. Please try again.')
            time.sleep(2)
            continue
        run_executable(exe_info['name'])
        time.sleep(1)
if __name__ == '__main__':
    main()