/*
 * Правила для потока документов чат-бота.
 * Теги задают вес в scoring: critical / high / medium / low.
 * Коды findings формируются как YARA_<ИМЯ_ПРАВИЛА> и являются частью
 * публичного контракта API — переименование ломает клиентов.
 *
 * Имена объектов PDF ищутся БЕЗ `nocase`. Спецификация делает их
 * регистрозависимыми: `/js` — не `/JS`, и читатель PDF его не выполнит.
 * `nocase` здесь ничего не ловил, зато утраивал число случайных совпадений
 * в сжатых потоках. Именно так двенадцатимегабайтный договор получал
 * `YARA_PDF_JS_WITH_AUTOEXEC` весом 60: `/js` и `/aA` нашлись в бинарном
 * мусоре (M7.1).
 *
 * Короткие имена (`/JS`, `/AA`) требуют за собой разделителя PDF. Три байта
 * без границы в мегабайтах сжатого потока встречаются по случайности почти
 * наверняка — это не эвристика, а арифметика.
 *
 * Чего эти правила принципиально не видят: имя, записанное через escape
 * (`/J#61vaScript`), и содержимое сжатых потоков. Это работа стадии
 * `structure`, которая разбирает документ, а не сканирует байты. YARA здесь —
 * дешёвая сетка поверх, а не замена разбору.
 */

rule pdf_js_with_autoexec : high
{
    meta:
        description = "PDF с JavaScript и автозапуском"
    strings:
        $pdf = "%PDF-"
        $js1 = "/JavaScript"
        $js2 = /\/JS[\s\/\[<(]/
        $auto1 = "/OpenAction"
        $auto2 = /\/AA[\s\/\[<(]/
    condition:
        $pdf at 0 and any of ($js*) and any of ($auto*)
}

rule pdf_launch_action : critical
{
    meta:
        description = "PDF пытается запустить внешнюю программу"
    strings:
        $pdf = "%PDF-"
        $launch = "/Launch"
    condition:
        $pdf at 0 and $launch
}

rule pdf_embedded_executable : critical
{
    meta:
        description = "PE-файл внутри PDF"
    strings:
        $pdf = "%PDF-"
        $embed = "/EmbeddedFile"
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
