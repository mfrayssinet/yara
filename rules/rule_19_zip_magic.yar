rule ZIP_Magic_Sus_19 {
  meta: author = "Pack" description = "Detect ZIP magic + malware mention" example = "19"
  strings:
    $zip = { 50 4B 03 04 }
    $m = "malware.exe" ascii nocase
  condition:
    $zip at 0 and $m
}