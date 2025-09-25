rule SQL_Union_InfSchema_15 {
  meta: author = "Pack" description = "Detect UNION SELECT + INFORMATION_SCHEMA" example = "15"
  strings:
    $u = "UNION SELECT" nocase
    $i = "INFORMATION_SCHEMA" nocase
  condition:
    $u and $i
}