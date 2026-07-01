# -*- mode: python ; coding: utf-8 -*-

import sys, os

block_cipher = None
PROJECT_ROOT = os.path.abspath(os.path.join(SPEC, '..', '..'))

a = Analysis(
    [os.path.join(PROJECT_ROOT, 'services', 'benguelashield_service.py')],
    pathex=[PROJECT_ROOT],
    binaries=[
        (os.path.join(PROJECT_ROOT, 'engine', 'clamav', 'x64', 'clamscan.exe'), 'engine'),
        (os.path.join(PROJECT_ROOT, 'engine', 'clamav', 'x64', 'clamd.exe'), 'engine'),
    ],
    datas=[
        (os.path.join(PROJECT_ROOT, 'config'), 'config'),
        (os.path.join(PROJECT_ROOT, 'modules', 'yara_engine', 'rules'), os.path.join('modules', 'yara_engine', 'rules')),\n    ],
    hiddenimports=[
        'win32serviceutil', 'win32service', 'win32event', 'win32timezone',
        'servicemanager', 'pywintypes', 'psutil', 'watchdog', 'yara',
        'lightgbm', 'lief', 'numpy', 'sklearn', 'Crypto',
    ],
    excludes=['tkinter', 'matplotlib', 'PyQt6', 'PIL'],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='BenguelaShieldService', debug=False, strip=False, upx=True, console=True)
coll = COLLECT(exe, a.binaries, a.zipfiles, a.datas, strip=False, upx=True, name='BenguelaShieldService')
