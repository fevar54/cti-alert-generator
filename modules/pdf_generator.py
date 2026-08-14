import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(data, output_filename="reporte_alerta_cti.pdf"):
    """
    Genera un PDF profesional utilizando ReportLab basado en la estructura de la amenaza CTI.
    """
    doc = SimpleDocTemplate(output_filename, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    styles = getSampleStyleSheet()

    # Estilos personalizados
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=15
    )
    
    heading_style = ParagraphStyle(
        'HeadingStyle',
        parent=styles['Heading2'],
        fontSize=13,
        textColor=colors.HexColor('#2980b9'),
        spaceBefore=10,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyStyle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#333333'),
        spaceAfter=8,
        leading=14
    )

    # Contenido del PDF
    story.append(Paragraph(f"<b>🚨 {data.get('title')}</b>", title_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#3498db'), spaceAfter=15))

    story.append(Paragraph("<b>Resumen de la Amenaza:</b>", heading_style))
    story.append(Paragraph(data.get('description'), body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("<b>Mapeo TTPs (MITRE ATT&CK):</b>", heading_style))
    for tactic in data.get("tactics", []):
        story.append(Paragraph(f"<b>Táctica: {tactic['tactic']} ({tactic['id']})</b>", body_style))
        for tech in tactic.get("techniques", []):
            story.append(Paragraph(f"• <b>{tech['id']} - {tech['name']}</b>: {tech['description']}", body_style))
        story.append(Spacer(1, 5))

    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>Recomendaciones de Mitigación y SOC:</b>", heading_style))
    for rec in data.get("recommendations", []):
        story.append(Paragraph(f"• {rec}", body_style))

    # Construir PDF
    doc.build(story)
    print(f"📄 Reporte PDF generado con éxito: {output_filename}")
    return output_filename