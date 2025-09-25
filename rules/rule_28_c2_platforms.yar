rule C2_Common_Platforms_28 {
  meta: author = "Pack" description = "Detect mention of popular C2-over-platforms" example = "28"
  strings:
    $t = "api.telegram.org" nocase
    $d = "discordapp.com" nocase
  condition:
    any of them
}