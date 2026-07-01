# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — BenguelaShield Service"""
import sys, os
from PyInstaller.utils.hooks import collect_all

block_cipher = None
PROJECT_ROOT = os.path.abspath(os.path.join(SPEC, '..', '..'))

sklearn_datas, sklearn_binaries, sklearn_hiddenimports = collect_all('sklearn')

a = Analysis(
    [os.path.join(PROJECT_ROOT, 'services', 'benguelashield_service.py')],
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
    ] + sklearn_datas,
    hiddenimports=[
        'win32serviceutil', 'win32service', 'win32event', 'win32timezone',
        'win32evtlog', 'servicemanager', 'pywintypes',
        'psutil', 'watchdog', 'watchdog.observers', 'watchdog.events',
        'yara', 'lightgbm', 'lief', 'numpy',
        'Crypto', 'Crypto.Cipher', 'Crypto.Cipher.AES', 'Crypto.Util.Padding',
        'requests', 'joblib',
    ] + sklearn_hiddenimports,
    excludes=['tkinter', 'matplotlib', 'PyQt6', 'PIL', 'scipy'],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='BenguelaShieldService',
    debug=False,
    strip=False,
    upx=True,
    console=True,
    uac_admin=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name='BenguelaShieldService',
)
