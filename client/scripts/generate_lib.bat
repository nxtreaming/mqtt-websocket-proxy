@echo off
echo Generating .lib files from .def files...

cd /d "%~dp0"

REM Check if lib.exe is available
where lib.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: lib.exe not found. Please run this from a Visual Studio Developer Command Prompt.
    echo Or make sure Visual Studio Build Tools are installed and in PATH.
    pause
    exit /b 1
)

REM Generate libmpg123-0.lib from libmpg123-0.def
if exist "libs\libmpg123-0.def" (
    echo Generating libmpg123-0.lib...
    lib /def:libs\libmpg123-0.def /out:libs\libmpg123-0.lib /machine:x64
    if %errorlevel% equ 0 (
        echo Successfully generated libmpg123-0.lib
    ) else (
        echo Failed to generate libmpg123-0.lib
    )
) else (
    echo Warning: libs\libmpg123-0.def not found
)

REM Generate libout123-0.lib from libout123-0.def
if exist "libs\libout123-0.def" (
    echo Generating libout123-0.lib...
    lib /def:libs\libout123-0.def /out:libs\libout123-0.lib /machine:x64
    if %errorlevel% equ 0 (
        echo Successfully generated libout123-0.lib
    ) else (
        echo Failed to generate libout123-0.lib
    )
) else (
    echo Warning: libs\libout123-0.def not found
)

REM Generate libsyn123-0.lib from libsyn123-0.def
if exist "libs\libsyn123-0.def" (
    echo Generating libsyn123-0.lib...
    lib /def:libs\libsyn123-0.def /out:libs\libsyn123-0.lib /machine:x64
    if %errorlevel% equ 0 (
        echo Successfully generated libsyn123-0.lib
    ) else (
        echo Failed to generate libsyn123-0.lib
    )
) else (
    echo Warning: libs\libsyn123-0.def not found
)

REM Generate libao.lib for x64 from libao.dll
if exist "libs\libao.dll" (
    echo Generating libao.def from libao.dll...
    dumpbin /exports libs\libao.dll > libs\libao_exports.txt
    
    echo Creating libao.def file...
    echo EXPORTS > libs\libao.def
    
    REM Extract function names from dumpbin output and add to .def file
    for /f "skip=19 tokens=4" %%i in (libs\libao_exports.txt) do (
        if not "%%i"=="" (
            if not "%%i"=="name" (
                echo %%i >> libs\libao.def
            )
        )
    )
    
    echo Generating libao_x64.lib...
    lib /def:libs\libao.def /out:libs\libao_x64.lib /machine:x64
    if %errorlevel% equ 0 (
        echo Successfully generated libao_x64.lib
        echo Replacing old libao.lib with x64 version...
        copy libs\libao_x64.lib libs\libao.lib
    ) else (
        echo Failed to generate libao_x64.lib
    )
    
    REM Clean up temporary files
    del libs\libao_exports.txt 2>nul
    del libs\libao.exp 2>nul
) else (
    echo Warning: libs\libao.dll not found
)

echo.
echo Done! Generated .lib files should now be in the libs directory.
echo You can now build the project with CMake.
pause
