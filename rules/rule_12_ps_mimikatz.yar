rule PS_Mimikatz_12 {
  meta: author = "Pack" description = "Detect 'mimikatz' keyword" example = "12"
  strings:
    $a = "mimikatz" nocase
  condition:
    $a
}