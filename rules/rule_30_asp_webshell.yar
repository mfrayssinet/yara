rule ASP_Webshell_Generic_30 {
  meta: author = "Pack" description = "Detect classic ASP eval request webshell" example = "30"
  strings:
    $a = "eval request(" nocase
  condition:
    $a
}