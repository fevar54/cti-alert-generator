def generate_html_alert(data):
    """
    Genera el contenido HTML estructurado para la alerta CTI basado en los TTPs de MITRE.
    """
    tactics_html = ""
    for tactic in data.get("tactics", []):
        techniques_html = ""
        for tech in tactic.get("techniques", []):
            techniques_html += f"""
                <li>
                    <strong>{tech['id']} - {tech['name']}</strong>: {tech['description']}
                </li>
            """
        
        tactics_html += f"""
            <div style="margin-bottom: 15px;">
                <h4 style="color: #d9534f; margin-bottom: 5px;">Táctica: {tactic['tactic']} ({tactic['id']})</h4>
                <ul style="margin: 0; padding-left: 20px;">
                    {techniques_html}
                </ul>
            </div>
        """

    recommendations_html = ""
    for rec in data.get("recommendations", []):
        recommendations_html += f"<li>{rec}</li>"

    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <title>{data.get('title', 'Alerta CTI')}</title>
    </head>
    <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6; background-color: #f8f9fa; padding: 20px;">
        <div style="max-width: 700px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h2 style="color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px;">🚨 {data.get('title')}</h2>
            
            <p><strong>Resumen de la Amenaza:</strong></p>
            <p>{data.get('description')}</p>
            
            <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
            
            <h3 style="color: #2c3e50;">📊 Mapeo TTPs (MITRE ATT&CK)</h3>
            {tactics_html}
            
            <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">
            
            <h3 style="color: #2c3e50;">🛡️ Recomendaciones de Mitigación y SOC</h3>
            <ul style="padding-left: 20px;">
                {recommendations_html}
            </ul>
            
            <p style="font-size: 12px; color: #7f8c8d; margin-top: 30px; text-align: center;">
                Generado automáticamente por CTI Alert Generator • MNEMO SOC
            </p>
        </div>
    </body>
    </html>
    """
    return html_content