rule PHP_Webshell_Keywords_07 {
  meta: author = "Pack" description = "Detect common PHP webshell keywords" example = "07"
  strings:
    $s1 = "eval(" nocase
    $s2 = "base64_decode(" nocase
    $s3 = "shell_exec(" nocase
    $s4 = "assert(" nocase
  condition:
    2 of ($s*)
}