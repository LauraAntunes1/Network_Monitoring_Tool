@echo Capture in progress, click on "Stop capture" to stop it.
@echo off
set /a id=%1
%SystemRoot%\Sysnative\cmd.exe /c "pktmon start -c -m rt --pkt-size 0 --comp %id% 1> ..\Captures\capture.txt 2> ..\error_start.txt"