rule Py_Base64_Exec_29 {
  meta: author = "Pack" description = "Detect python base64 + exec" example = "29"
  strings:
    $b = "base64.b64decode" nocase
    $e = "exec(" nocase
  condition:
    $b and $e
}