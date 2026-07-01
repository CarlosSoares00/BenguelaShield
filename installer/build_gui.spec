# -*- mode: python ; coding: utf-8 -*-

import sys, os
from pathlib import Path

block_cipher = None
PROJECT_ROOT = os.path.abspath(os.path.join(SPEC, '..', '..'))

a = Analysis(
    [os.path.join(PROJECT_ROOT, 'main_gui.py')],
    pathex=[PROJECT_ROOT],
    binaries=[
        (os.path.join(PROJECT_ROOT, 'engine', 'clamav', 'x64', 'clamscan.exe'), 'engine'),
        (os.path.join(PROJECT_ROOT, 'engine', 'clamav', 'x64', 'clamd.exe'), 'engine'),
        (os.path.join(PROJECT_ROOT, 'engine', 'clamav', 'x64', 'freshclam.exe'), 'engine'),
    ],
    datas=[
        (os.path.join(PROJECT_ROOT, 'config'), 'config'),
        (os.path.join(PROJECT_ROOT, 'modules', 'yara_engine', 'rules'), os.path.join('modules', 'yara_engine', 'rules')),\n        (os.path.join(PROJECT_ROOT, 'modules', 'ai', 'models'), os.path.join('modules', 'ai', 'models')),\n        (os.path.join(PROJECT_ROOT, 'setup_info.py'), '.'),
    ],
    hiddenimports=[
        'PyQt6.QtWidgets', 'PyQt6.QtCore', 'PyQt6.QtGui',
        'win32api', 'win32con', 'win32file', 'win32process',
        'win32security', 'win32service', 'win32serviceutil',
        'pywintypes', 'lightgbm', 'lief', 'numpy',
        'sklearn', 'yara', 'psutil', 'watchdog',
        'Crypto', 'Crypto.Cipher.AES', 'requests',
    ],
    excludes=['tkinter', 'matplotlib', 'PIL'],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='BenguelaShield', debug=False, strip=False, upx=True, console=False)
coll = COLLECT(exe, a.binaries, a.zipfiles, a.datas, strip=False, upx=True, name='BenguelaShield')
