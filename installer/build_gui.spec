# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — BenguelaShield GUI"""
import sys, os
from PyInstaller.utils.hooks import collect_all

block_cipher = None
PROJECT_ROOT = os.path.abspath(os.path.join(SPEC, '..', '..'))

sklearn_datas, sklearn_binaries, sklearn_hiddenimports = collect_all('sklearn')

a = Analysis(
    [os.path.join(PROJECT_ROOT, 'main_gui.py')],
    pathex=[PROJECT_ROOT],
    binaries=[
        (os.path.join(PROJECT_ROOT, 'engine', 'clamav', 'x64', 'clamscan.exe'), 'engine'),
        (os.path.join(PROJECT_ROOT, 'engine', 'clamav', 'x64', 'clamd.exe'), 'engine'),
        (os.path.join(PROJECT_ROOT, 'engine', 'clamav', 'x64', 'freshclam.exe'), 'engine'),
    ] + sklearn_binaries,
    datas=[
        (os.path.join(PROJECT_ROOT, 'config'), 'config'),
        (os.path.join(PROJECT_ROOT, 'modules', 'yara_engine', 'rules'), os.path.join('modules', 'yara_engine', 'rules')),
        (os.path.join(PROJECT_ROOT, 'modules', 'ai', 'models'), os.path.join('modules', 'ai', 'models')),
        (os.path.join(PROJECT_ROOT, 'setup_info.py'), '.'),
    ] + sklearn_datas,
    hiddenimports=[
        'PyQt6.QtWidgets', 'PyQt6.QtCore', 'PyQt6.QtGui',
        'PyQt6.sip',
        'win32api', 'win32con', 'win32event', 'win32file', 'win32process',
        'win32security', 'win32service', 'win32serviceutil',
        'win32evtlog', 'win32timezone', 'servicemanager', 'pywintypes',
        'lightgbm', 'lief', 'numpy',
        'yara', 'psutil',
        'watchdog', 'watchdog.observers', 'watchdog.events',
        'Crypto', 'Crypto.Cipher', 'Crypto.Cipher.AES', 'Crypto.Util.Padding',
        'requests', 'joblib',
    ] + sklearn_hiddenimports,
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
    version=os.path.join(PROJECT_ROOT, 'installer', 'version_info.py'),
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
