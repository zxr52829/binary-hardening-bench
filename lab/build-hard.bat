@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cl /nologo /Od /Ob0 /GS- /Fe:target-hard.exe /Fo:target-hard.obj target-hard.c
echo EXITCODE=%ERRORLEVEL%
