rule PDF_OpenAction_20 {
  meta: author = "Pack" description = "Detect PDF with OpenAction" example = "20"
  strings:
    $pdf = "%PDF" ascii
    $oa  = "/OpenAction" ascii
  condition:
    $pdf at 0 and $oa
}