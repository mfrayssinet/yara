rule Batch_PowerShell_Call_05 {
  meta: author = "Pack" description = "Batch file invoking PowerShell with -enc" example = "05"
  strings:
    $a = ".bat" ascii
    $b = "powershell -nop" nocase
    $c = " -enc " nocase
  condition:
    $b and $c
}