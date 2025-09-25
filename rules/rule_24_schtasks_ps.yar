rule SchTasks_PS_24 {
  meta: author = "Pack" description = "Detect schtasks XML invoking PowerShell" example = "24"
  strings:
    $a = "<Task>" ascii
    $p = "<Command>powershell</Command>" ascii nocase
  condition:
    $a and $p
}