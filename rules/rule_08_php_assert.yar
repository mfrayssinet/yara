rule PHP_Assert_Eval_08 {
  meta: author = "Pack" description = "Detect PHP assert backdoor" example = "08"
  strings:
    $a = "assert(" nocase
  condition:
    $a
}