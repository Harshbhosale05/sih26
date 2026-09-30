"""Server-side PDF export.

Renders the exact HTML report with WeasyPrint, so the PDF, the HTML and the
JSON exports are three views of one payload and cannot disagree. Page size,
running headers, footers and page numbers come from the template's @page rules.
"""

from __future__ import annotations


def render_pdf(html: str) -> bytes:
    from weasyprint import HTML  # imported lazily: pango is only needed for PDF

    return HTML(string=html).write_pdf()
