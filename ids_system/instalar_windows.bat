@echo off
:: =============================================================
::   SISTEMA IDS INSTITUCIONAL - Script de Instalación Windows
::   Ejecutar como Administrador
:: =============================================================

title IDS Institucional - Instalador

echo.
echo  =====================================================
echo   Sistema IDS Institucional v1.0 - Instalador
echo   Ejecutar como Administrador
echo  =====================================================
echo.

:: Verificar Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python no encontrado. Descarga Python 3.10+ desde:
    echo         https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [OK] Python encontrado.

:: Verificar pip
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip no encontrado.
    pause
    exit /b 1
)

:: Instalar dependencias Python
echo.
echo [*] Instalando dependencias Python...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Fallo al instalar dependencias.
    pause
    exit /b 1
)
echo [OK] Dependencias instaladas.

:: Crear directorios necesarios
echo.
echo [*] Creando estructura de directorios...
if not exist "config" mkdir config
if not exist "logs"   mkdir logs
if not exist "reports" mkdir reports
echo [OK] Directorios creados.

:: Crear .env si no existe
if not exist ".env" (
    echo.
    echo [*] Creando archivo .env desde plantilla...
    copy .env.example .env
    echo [IMPORTANTE] Edita el archivo .env con tus credenciales SMTP.
) else (
    echo [OK] Archivo .env ya existe.
)

:: Recordatorio de Npcap
echo.
echo  =====================================================
echo   PASO MANUAL REQUERIDO:
echo   Instala Npcap desde https://npcap.com/#download
echo   (necesario para captura de paquetes en Windows)
echo  =====================================================
echo.

echo [*] Instalacion completada.
echo [*] Edita .env con tus datos SMTP y ejecuta:
echo     python ids_main.py
echo.
pause
