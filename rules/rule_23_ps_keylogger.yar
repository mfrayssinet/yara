rule PS_Keylogger_API_23 {
  meta: author = "Pack" description = "Detect GetAsyncKeyState in PowerShell" example = "23"
  strings:
    $a = "GetAsyncKeyState" nocase
    $u = "user32.dll" nocase
  condition:
    $a and $u
}