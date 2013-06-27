@echo off
if not x%1x==xx goto nextfile
echo Guardtime simplified signature verification tool.
echo Please run as:
echo %0 file1 file2 fileX 
echo in order to verify the signatures on files named file1, file2 and fileX.
echo Use 'gtime-sign' to sign files.
goto end


:nextfile
shift
if x%0x==xx goto end
echo Verifying %0:
if not exist %0.gtts goto nosig
if not exist %0 goto nofile

gtime -v -p -x -f %0 -i %0.gtts  | find /v "GT_"

goto nextfile

:nosig
echo Error: Cannot find signature file %0.gtts.
goto nextfile

:nofile
echo Error: Cannot find file named %0.
goto nextfile

:end
