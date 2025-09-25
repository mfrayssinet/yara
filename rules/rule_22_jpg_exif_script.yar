rule JPEG_EXIF_Script_22 {
  meta: author = "Pack" description = "Detect JPEG header + script tag" example = "22"
  strings:
    $jpg = { FF D8 FF }
    $sc  = "<script>" ascii nocase
  condition:
    $jpg at 0 and $sc
}