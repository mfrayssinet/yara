rule PS_EncodedCommand_Easy_01 {
  meta: author = "Pack" description = "Detect PowerShell -EncodedCommand" example = "01"
  strings:
    $a = "-EncodedCommand" nocase
    $b = " -enc " nocase
  condition:
    any of them
}
