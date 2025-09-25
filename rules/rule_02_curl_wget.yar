rule Curl_Wget_Downloaders_02 {
  meta: author = "Pack" description = "Detect curl/wget http downloads" example = "02"
  strings:
    $c = "curl http" nocase
    $w = "wget http" nocase
  condition:
    any of them
}