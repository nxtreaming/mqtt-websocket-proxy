# PowerShell script to generate .lib files from .def files
Write-Host "Generating .lib files from .def files..." -ForegroundColor Green

# Change to script directory
Set-Location $PSScriptRoot

# Check if lib.exe is available
$libExe = Get-Command lib.exe -ErrorAction SilentlyContinue
if (-not $libExe) {
    Write-Host "Error: lib.exe not found. Please run this from a Visual Studio Developer PowerShell." -ForegroundColor Red
    Write-Host "Or make sure Visual Studio Build Tools are installed and in PATH." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Function to generate lib file from def file
function Generate-LibFile {
    param(
        [string]$DefFile,
        [string]$LibFile
    )
    
    if (Test-Path $DefFile) {
        Write-Host "Generating $LibFile..." -ForegroundColor Yellow
        $result = & lib.exe /def:$DefFile /out:$LibFile /machine:x64
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully generated $LibFile" -ForegroundColor Green
        } else {
            Write-Host "Failed to generate $LibFile" -ForegroundColor Red
        }
    } else {
        Write-Host "Warning: $DefFile not found" -ForegroundColor Yellow
    }
}

# Generate lib files
Generate-LibFile "libs\libmpg123-0.def" "libs\libmpg123-0.lib"
Generate-LibFile "libs\libout123-0.def" "libs\libout123-0.lib"
Generate-LibFile "libs\libsyn123-0.def" "libs\libsyn123-0.lib"

# Generate libao.lib for x64 from libao.dll
if (Test-Path "libs\libao.dll") {
    Write-Host "Generating libao.def from libao.dll..." -ForegroundColor Yellow
    
    # Use dumpbin to get exports
    $dumpbinOutput = & dumpbin.exe /exports libs\libao.dll
    
    # Create .def file
    Write-Host "Creating libao.def file..." -ForegroundColor Yellow
    $defContent = @("EXPORTS")
    
    # Parse dumpbin output to extract function names
    $inExportsSection = $false
    foreach ($line in $dumpbinOutput) {
        if ($line -match "^\s*ordinal\s+hint\s+RVA\s+name") {
            $inExportsSection = $true
            continue
        }
        if ($inExportsSection -and $line -match "^\s*\d+\s+[0-9A-F]+\s+[0-9A-F]+\s+(\w+)") {
            $functionName = $matches[1]
            if ($functionName -and $functionName -ne "name") {
                $defContent += $functionName
            }
        }
        if ($inExportsSection -and $line -match "^\s*Summary") {
            break
        }
    }
    
    # Write .def file
    $defContent | Out-File -FilePath "libs\libao.def" -Encoding ASCII
    
    Write-Host "Generating libao_x64.lib..." -ForegroundColor Yellow
    $result = & lib.exe /def:libs\libao.def /out:libs\libao_x64.lib /machine:x64
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Successfully generated libao_x64.lib" -ForegroundColor Green
        Write-Host "Replacing old libao.lib with x64 version..." -ForegroundColor Yellow
        Copy-Item "libs\libao_x64.lib" "libs\libao.lib" -Force
    } else {
        Write-Host "Failed to generate libao_x64.lib" -ForegroundColor Red
    }
    
    # Clean up temporary files
    Remove-Item "libs\libao.exp" -ErrorAction SilentlyContinue
} else {
    Write-Host "Warning: libs\libao.dll not found" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done! Generated .lib files should now be in the libs directory." -ForegroundColor Green
Write-Host "You can now build the project with CMake." -ForegroundColor Green
Read-Host "Press Enter to exit"
