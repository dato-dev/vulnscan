/*
 * Правила для потока документов чат-бота.
 * Теги задают вес в scoring: critical / high / medium / low.
 * Коды findings формируются как YARA_<ИМЯ_ПРАВИЛА> и являются частью
 * публичного контракта API — переименование ломает клиентов.
 */

rule pdf_js_with_autoexec : high
{
    meta:
        description = "PDF с JavaScript и автозапуском"
    strings:
        $pdf = "%PDF-"
        $js1 = "/JavaScript" nocase
        $js2 = "/JS" nocase
        $auto1 = "/OpenAction" nocase
        $auto2 = "/AA" nocase
    condition:
        $pdf at 0 and any of ($js*) and any of ($auto*)
}

rule pdf_launch_action : critical
{
    meta:
        description = "PDF пытается запустить внешнюю программу"
    strings:
        $pdf = "%PDF-"
        $launch = "/Launch" nocase
    condition:
        $pdf at 0 and $launch
}

rule pdf_embedded_executable : critical
{
    meta:
        description = "PE-файл внутри PDF"
    strings:
        $pdf = "%PDF-"
        $embed = "/EmbeddedFile" nocase
        $mz = { 4D 5A 90 00 03 00 00 00 }
    condition:
        $pdf at 0 and $embed and $mz
}

rule image_with_script_payload : medium
{
    meta:
        description = "Скриптовый payload в теле изображения"
    strings:
        $jpg = { FF D8 FF }
        $png = { 89 50 4E 47 0D 0A 1A 0A }
        $php = "<?php"
        $script = "<script" nocase
        $eval = "eval(" nocase
    condition:
        ($jpg at 0 or $png at 0) and any of ($php, $script, $eval)
}
