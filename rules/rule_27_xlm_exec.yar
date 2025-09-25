rule XLM_Macro_EXEC_27 {
  meta: author = "Pack" description = "Detect Excel 4.0 macro EXEC" example = "27"
  strings:
    $a = "Auto_Open" nocase
    $e = "=EXEC(" nocase
  condition:
    $a and $e
}