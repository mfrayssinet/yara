rule ELF_Magic_Shell_18 {
  meta: author = "Pack" description = "Detect ELF magic + /bin/sh ref" example = "18"
  strings:
    $elf = { 7F 45 4C 46 }
    $sh = "/bin/sh" ascii
  condition:
    $elf at 0 and $sh
}