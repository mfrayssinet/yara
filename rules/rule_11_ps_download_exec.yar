rule PS_Download_Exec_11 {
  meta: author = "Pack" description = "Detect Invoke-WebRequest + IEX" example = "11"
  strings:
    $d = "Invoke-WebRequest" nocase
    $e = "IEX(" nocase
  condition:
    $d and $e
}