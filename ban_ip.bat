@echo off
set ip=%1
%SystemRoot%\Sysnative\cmd.exe /c "netsh advfirewall firewall add rule name="Monitoring" dir=in interface=any remoteip=%ip% action=block > ..\error_ban.txt"