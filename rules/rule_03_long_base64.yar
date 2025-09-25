rule Long_Base64_Snippet_03 {
  meta: author = "Pack" description = "Detect long base64-ish strings" example = "03"
  strings:
    $b64 = /[A-Za-z0-9+\/]{80,}={0,2}/
  condition:
    #b64 > 0
}