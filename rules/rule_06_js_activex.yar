rule JS_ActiveX_Sus_06 {
  meta: author = "Pack" description = "Detect ActiveXObject usage" example = "06"
  strings:
    $ax = "ActiveXObject" nocase
  condition:
    $ax
}