rule DLL_Magic_Suspicious_17 {
  meta: author = "Pack" description = "Detect DLL MZ + DllMain + URL" example = "17"
  strings:
    $mz = { 4D 5A }
    $d = "DllMain" ascii nocase
    $u = /https?:\/\/[a-z0-9\.\-]+/ nocase
  condition:
    $mz at 0 and $d and $u
}