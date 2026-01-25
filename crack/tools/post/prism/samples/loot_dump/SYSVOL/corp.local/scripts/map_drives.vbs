' =====================================================
' Drive Mapping Script for Corp Domain
' Version: 2.1
' Last Modified: 2025-11-15
' =====================================================

Option Explicit

Dim objNetwork, objShell, strUser, strDept
Dim objFSO, strLogFile, objLogFile

Set objNetwork = CreateObject("WScript.Network")
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

strUser = objNetwork.UserName
strLogFile = "\\logsvr\logs\" & objNetwork.ComputerName & "\mapdrives.log"

' Create log entry
Sub WriteLog(strMessage)
    On Error Resume Next
    If objFSO.FileExists(strLogFile) Then
        Set objLogFile = objFSO.OpenTextFile(strLogFile, 8, True)
    Else
        Set objLogFile = objFSO.CreateTextFile(strLogFile, True)
    End If
    objLogFile.WriteLine Now & " - " & strUser & " - " & strMessage
    objLogFile.Close
    On Error Goto 0
End Sub

' Remove existing drives
On Error Resume Next
objNetwork.RemoveNetworkDrive "H:", True, True
objNetwork.RemoveNetworkDrive "S:", True, True
objNetwork.RemoveNetworkDrive "P:", True, True
On Error Goto 0

' Map user home drive
WriteLog "Mapping H: to user home folder"
objNetwork.MapNetworkDrive "H:", "\\filesvr\users\" & strUser, False

' Map shared drive
WriteLog "Mapping S: to shared folder"
objNetwork.MapNetworkDrive "S:", "\\filesvr\shared", False

' Map projects drive based on department
strDept = objShell.RegRead("HKCU\Software\Corp\Department")
If strDept <> "" Then
    WriteLog "Mapping P: to department folder: " & strDept
    objNetwork.MapNetworkDrive "P:", "\\filesvr\projects\" & strDept, False
End If

WriteLog "Drive mapping complete"

Set objNetwork = Nothing
Set objShell = Nothing
Set objFSO = Nothing
