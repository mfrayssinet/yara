rule DOCX_ZIP_Sign_21 {
  meta: author = "Pack" description = "Detect DOCX-like ZIP signature + parts" example = "21"
  strings:
    $zip = { 50 4B 03 04 }
    $ct  = "[Content_Types].xml" ascii
    $wd  = "word/document.xml" ascii
  condition:
    $zip at 0 and 1 of ($ct,$wd)
}