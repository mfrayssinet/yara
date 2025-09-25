rule Macro_VBA_AutoOpen_10 {
  meta: author = "Pack" description = "Detect VBA AutoOpen + Wscript.Shell" example = "10"
  strings:
    $a = "AutoOpen" nocase
    $b = "CreateObject("Wscript.Shell")" nocase
  condition:
    $a and $b
}