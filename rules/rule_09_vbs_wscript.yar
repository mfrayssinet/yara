rule VBS_WScriptShell_09 {
  meta: author = "Pack" description = "Detect WScript.Shell in VBS" example = "09"
  strings:
    $a = "WScript.Shell" nocase
  condition:
    $a
}