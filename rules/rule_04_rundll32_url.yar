rule Rundll32_URL_04 {
  meta: author = "Pack" description = "Detect rundll32 with URL" example = "04"
  strings:
    $r = "rundll32" nocase
    $u = /https?:\/\/[a-z0-9\.\-]+/ nocase
  condition:
    $r and $u
}