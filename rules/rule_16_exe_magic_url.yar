rule EXE_Magic_URL_16 {
  meta: author = "Pack" description = "Detect MZ magic + URL" example = "16"
  strings:
    $mz = { 4D 5A }
    $u = /https?:\/\/[a-z0-9\.\-]+/ nocase
  condition:
    $mz at 0 and $u
}