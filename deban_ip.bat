@echo off
set ip=%1
%SystemRoot%\Sysnative\cmd.exe /c "netsh advfirewall firewall delete rule name="Monitoring" remoteip=%ip% > ..\error_deban.txt"