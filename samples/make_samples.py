"""Генерация тестовых файлов. Реальные вредоносы в репозиторий не кладём.

Документы собираются pikepdf, а не вручную: PDF, написанный по памяти, битый,
и тогда сэмпл «чистый документ» проверяет не то, что заявлено.

Запуск: python samples/make_samples.py
"""

from __future__ import annotations

import sys
from pathlib import Path

OUT = Path(__file__).parent / "generated"

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _document(pikepdf, pages: int = 1):
    pdf = pikepdf.Pdf.new()
    for _ in range(pages):
        pdf.add_blank_page(page_size=(595, 842))
    return pdf


def main() -> int:
    try:
        import pikepdf
    except ImportError:
        print("нужен pikepdf: pip install pikepdf")
        return 1

    OUT.mkdir(exist_ok=True)

    _document(pikepdf).save(OUT / "benign.pdf")

    pdf = _document(pikepdf)
    pdf.Root["/OpenAction"] = pdf.make_indirect(
        pikepdf.Dictionary(S=pikepdf.Name("/JavaScript"), JS=pikepdf.String("app.alert(1);"))
    )
    pdf.save(OUT / "pdf_openaction_js.pdf")

    pdf = _document(pikepdf)
    pdf.Root["/OpenAction"] = pdf.make_indirect(
        pikepdf.Dictionary(S=pikepdf.Name("/Launch"), F=pikepdf.String("calc.exe"))
    )
    pdf.save(OUT / "pdf_launch.pdf")

    pdf = _document(pikepdf)
    annot = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/Annot"),
            Subtype=pikepdf.Name("/Widget"),
            Rect=pikepdf.Array([0, 0, 10, 10]),
            F=2,
            A=pikepdf.Dictionary(S=pikepdf.Name("/Launch")),
        )
    )
    pdf.pages[0]["/Annots"] = pikepdf.Array([annot])
    pdf.save(OUT / "pdf_hidden_annot.pdf")

    (OUT / "eicar.com").write_text(EICAR)

    # Polyglot: настоящий JPEG с приклеенным ZIP-хвостом.
    try:
        from PIL import Image

        photo = OUT / "polyglot.jpg"
        Image.new("RGB", (320, 240), (200, 200, 200)).save(photo, "JPEG")
        photo.write_bytes(photo.read_bytes() + b"PK\x03\x04" + b"\x00" * 64)
    except ImportError:
        print("Pillow недоступен, polyglot.jpg пропущен")

    # Документы Word и архивы (M6): по одному механизму на файл.
    import office_samples

    for name in (
        "clean_docx",
        "macro_docm",
        "dde_docx",
        "obfuscated_field_docx",
        "remote_template_docx",
        "remote_object_docx",
        "embedded_ole_docx",
        "altchunk_docx",
        "dtd_docx",
        "equation_editor_docx",
        "docvar_payload_docm",
    ):
        suffix = ".docm" if name.endswith("docm") else ".docx"
        (OUT / f"{name.rsplit('_', 1)[0]}{suffix}").write_bytes(getattr(office_samples, name)())
    (OUT / "zip_with_launch_pdf.zip").write_bytes(
        office_samples.zip_of({"invoice.pdf": (OUT / "pdf_launch.pdf").read_bytes()})
    )
    (OUT / "zip_bomb_declared.zip").write_bytes(
        office_samples.with_declared_size(
            office_samples.zip_of({"a.bin": b"1", "b.bin": b"2", "c.bin": b"3"}), 3_500_000_000
        )
    )
    (OUT / "zip_traversal.zip").write_bytes(
        office_samples.zip_of({"../../evil.pdf": (OUT / "benign.pdf").read_bytes()})
    )

    for path in sorted(OUT.iterdir()):
        print(f"{path.name}: {path.stat().st_size} байт")
    return 0


if __name__ == "__main__":
    sys.exit(main())
