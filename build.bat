@echo off
echo ========================================
echo  ZWinScan - Build EXE
echo ========================================
echo.

echo Memastikan dependensi terinstall...
py -m pip install pyinstaller pefile colorama google-genai PyQt6 --quiet

if exist "dist\ZWinScan.exe" del /f "dist\ZWinScan.exe"
if exist "build" rmdir /s /q "build"

echo.
echo Membangun ZWinScan.exe...
echo.
py -m PyInstaller zwinscan_gui.spec --clean

echo.
if exist "dist\ZWinScan.exe" (
    echo ========================================
    echo  BERHASIL! File: dist\ZWinScan.exe
    echo ========================================
    explorer dist
) else (
    echo ========================================
    echo  GAGAL. Cek error di atas.
    echo ========================================
)

pause
