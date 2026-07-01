# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec - BenguelaShield GUI"""
import sys, os

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
        (os.path.join(PROJECT_ROOT, 'modules', 'yara_engine', 'rules'), os.path.join('modules', 'yara_engine', 'rules')),
        (os.path.join(PROJECT_ROOT, 'modules', 'ai', 'models'), os.path.join('modules', 'ai', 'models')),
        (os.path.join(PROJECT_ROOT, 'setup_info.py'), '.'),
    ],
    hiddenimports=[
        'PyQt6.QtWidgets', 'PyQt6.QtCore', 'PyQt6.QtGui',
        'PyQt6.sip',
        'win32api', 'win32con', 'win32file', 'win32process',
        'win32security', 'win32service', 'win32serviceutil',
        'win32timezone', 'pywintypes',
        'lightgbm', 'lief', 'numpy',
        'sklearn', 'sklearn.ensemble', 'sklearn.ensemble._iforest',
        'yara', 'psutil',
        'watchdog', 'watchdog.observers', 'watchdog.events',
        'Crypto', 'Crypto.Cipher', 'Crypto.Cipher.AES', 'Crypto.Util.Padding',
        'requests',
    ],
    excludes=['tkinter', 'matplotlib', 'PIL', 'scipy'],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='BenguelaShield',
    debug=False,
    strip=False,
    upx=True,
    console=False,
    icon=os.path.join(PROJECT_ROOT, 'installer', 'assets', 'icon.ico'),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name='BenguelaShield',
)
