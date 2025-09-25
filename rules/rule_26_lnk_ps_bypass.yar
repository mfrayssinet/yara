rule LNK_PowerShell_26 {
  meta: author = "Pack" description = "Detect .lnk string with PowerShell bypass" example = "26"
  strings:
    $l = ".lnk" nocase
    $p = "ExecutionPolicy Bypass" nocase
  condition:
    $p
}