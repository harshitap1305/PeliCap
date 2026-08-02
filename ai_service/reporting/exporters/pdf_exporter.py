"""PDF exporter — converts rendered HTML to PDF using WeasyPrint."""
from weasyprint import HTML, CSS


def export_pdf(html_content: str, output_path: str):
    """
    Convert an HTML string to PDF and write it to output_path.
    Raises on failure — caller handles exception.
    """
    HTML(string=html_content, base_url=None).write_pdf(output_path)
