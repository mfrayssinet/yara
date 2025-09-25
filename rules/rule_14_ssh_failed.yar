rule SSH_Brute_Log_14 {
  meta: author = "Pack" description = "Detect 'Failed password' SSH logs" example = "14"
  strings:
    $a = "Failed password" nocase
  condition:
    #a >= 2
}