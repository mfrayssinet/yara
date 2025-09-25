rule Registry_Run_PS_25 {
  meta: author = "Pack" description = "Detect Run key launching PowerShell" example = "25"
  strings:
    $a = "CurrentVersion\\Run" nocase
    $p = "powershell" nocase
  condition:
    $a and $p
}