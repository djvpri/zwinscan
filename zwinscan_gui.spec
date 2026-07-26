# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['zwinscan_gui.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'pefile',
        'PyQt6.sip',
        'PyQt6.QtWidgets',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'google.genai',
        'google.genai.types',
        'google.auth',
        'google.auth.transport',
        'google.api_core',
        'httpx',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter', 'matplotlib', 'numpy', 'pandas',
        'scipy', 'IPython', 'jupyter',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ZWinScan',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='zwinscan.ico' if __import__('os').path.exists('zwinscan.ico') else None,
)
