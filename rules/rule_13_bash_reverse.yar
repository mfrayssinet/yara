rule Bash_Reverse_Shell_13 {
  meta: author = "Pack" description = "Detect bash reverse shell snippet" example = "13"
  strings:
    $a = "/dev/tcp/" nocase
  condition:
    $a
}