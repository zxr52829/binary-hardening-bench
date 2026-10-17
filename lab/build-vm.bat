@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cl /nologo /Od /Ob0 /GS- /Fe:target-vm.exe /Fo:target-vm.obj target-vm.c
echo EXITCODE=%ERRORLEVEL%
