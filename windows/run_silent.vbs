Set ws = CreateObject("Wscript.Shell")
Dim fso, scriptDir, pyw
Set fso = CreateObject("Scripting.FileSystemObject")
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

pyw = "pythonw.exe"
If fso.FileExists(ws.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\Python\Python314\pythonw.exe") Then
    pyw = """" & ws.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\Python\Python314\pythonw.exe"""
End If

ws.Run pyw & " """ & scriptDir & "\giwifi_login.py""", 0, False
