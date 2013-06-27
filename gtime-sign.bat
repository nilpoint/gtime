@echo off
if not x%1x==xx goto nextfile

echo Guardtime simplified signing tool.
echo Please run as:
echo %0 file1 file2 fileX 
echo in order to sign files named file1, file2 and fileX.
echo Use 'gtime-verify' to verify those signatures.
echo Note that signature tokens are stored into files named file1.gtts, file2.gtts etc.
goto end


:nextfile
shift
if x%0x==xx goto end
echo Signing %0:
if exist %0.gtts goto sigexists
if not exist %0 goto filenotexists

gtime -s -f %0 -o %0.gtts
if errorlevel 1 goto nextfile
echo OK, signature saved as %0.gtts

goto nextfile

:sigexists
echo Signature file %0.gtts already exists; skipping.
goto nextfile

:filenotexists
echo Error: Cannot find file named %0.
goto nextfile

:end
