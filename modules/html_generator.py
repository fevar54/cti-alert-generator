from datetime import datetime

def generate_html_alert(data):
    """
    Genera el contenido HTML estructurado para la alerta CTI (Preventive/Campañas) 
    utilizando la plantilla oficial del SOC de MNEMO.
    """
    # Obtener valores con respaldos predeterminados
    titulo = data.get('title', 'Cyber Security Warning')
    fecha = data.get('date', datetime.now().strftime('%Y-%m-%d %H:%M'))
    tlp = data.get('tlp', 'TLP:AMBER')
    prioridad = data.get('priority', 'Media')
    subcategoria = data.get('subcategory', 'Malware / Campaña')
    tipo_alerta = data.get('alert_type', 'Preventiva')
    sectores = data.get('sectors', 'General')
    
    # Threat Information
    numero_ioc = data.get('ioc_count', '0')
    pap = data.get('pap', 'PAP:AMBER')
    familia = data.get('family', 'N/A')
    adversary = data.get('adversary', 'Desconocido')
    
    # Descripción / Síntesis
    sintesis = data.get('description', 'Sin descripción disponible.')
    
    # TTPs / Técnicas
    tactics_html = ""
    for tactic in data.get("tactics", []):
        tech_items = ""
        techniques = tactic.get("techniques", [])
        for tech in techniques:
            if isinstance(tech, dict):
                tech_items += f"<li><b>{tech.get('id')} - {tech.get('name')}</b>: {tech.get('description')}</li>"
            else:
                tech_items += f"<li>{tech}</li>"
        
        tactics_html += f"""
            <div style="margin-bottom: 10px;">
                <b>Táctica: {tactic.get('tactic')} ({tactic.get('id')})</b>
                <ul style="margin: 5px 0 0 20px; padding: 0;">
                    {tech_items}
                </ul>
            </div>
        """
    if not tactics_html:
        tactics_html = "<span>No se especificaron tácticas detalladas en este reporte.</span>"

    # Mitigaciones
    mitigations_list = data.get('mitigations', [
        "Monitorear indicadores de compromiso (IoCs) en el perímetro y endpoints.",
        "Aplicar políticas de restricción de ejecución en sistemas críticos."
    ])
    mitigations_html = "".join([f"<li>{mit}</li>" for mit in mitigations_list])

    # Impacto y recomendaciones
    recs_list = data.get('recommendations', [
        "Actualizar las contramedidas y reglas de detección en el SIEM.",
        "Revisar los registros históricos ante patrones de comportamiento similares."
    ])
    recs_html = "".join([f"<li>{rec}</li>" for rec in recs_list])

    # Referencias
    refs_list = data.get('references', [
        "https://attack.mitre.org/"
    ])
    refs_html = "".join([f'<li><a href="{ref}" target="_blank" style="color: #3498db;">{ref}</a></li>' for ref in refs_list])

    # IoCs archivo o lista
    iocs_info = data.get('iocs_filename', 'Indicadores de compromiso incluidos en el adjunto o plataforma de gestión.')

    # Plantilla HTML oficial integrada
    html_content = f"""
<html>
  <body style="margin:0;background:rgb(238,238,238);font-family:Arial,sans-serif">
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:rgb(238,238,238);padding:10px 0">
      <tr>
        <td align="center">
          <table width="70%" cellpadding="0" cellspacing="0" border="0" style="background:rgb(246,247,246);border-collapse:collapse">
            
            <!-- Header imagen -->
            <tr>
              <td align="center" style="background:rgb(246,247,246);padding:10px 0">
                <img src="https://mnemo.com/wp-content/uploads/header_CTI-scaled.png" width="90%" alt="Header">
              </td>
            </tr>

            <!-- Título -->
            <tr>
              <td style="background:rgb(4,71,103);color:#fff;padding:12px 20px;font-weight:bold;font-size:15pt">
                Cyber Security Warning - Preventive
              </td>
            </tr>

            <!-- Subject -->
            <tr>
              <td style="background:#fff;border-bottom:1px solid rgb(224,225,227);padding:12px 10px 12px 15px">
                <span style="color:rgb(51,51,51);font-size:13pt;font-weight:bold">&nbsp;&nbsp;{titulo}</span>
              </td>
            </tr>

            <!-- Metadatos -->
            <tr>
              <td style="background:#fff;padding:10px 0">
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse">
                  <tr>
                    <td style="padding:10px 13px;width:20%">&nbsp;&nbsp;<b>Fecha:</b></td>
                    <td style="padding:10px 13px;width:30%">{fecha}&nbsp;&nbsp;</td>
                    <td style="padding:10px 13px;width:20%">&nbsp;&nbsp;<b>TLP:</b></td>
                    <td style="padding:10px 13px;width:30%">{tlp}</td>
                  </tr>
                  <tr>
                    <td style="padding:10px 13px">&nbsp;&nbsp;<b>Criticidad:</b></td>
                    <td style="padding:10px 13px">{prioridad}&nbsp;&nbsp;</td>
                    <td style="padding:10px 13px">&nbsp;&nbsp;<b>Taxonomía:</b></td>
                    <td style="padding:10px 13px">{subcategoria}</td>
                  </tr>
                  <tr>
                    <td style="padding:10px 13px">&nbsp;&nbsp;<b>Tipo de alerta:</b></td>
                    <td style="padding:10px 13px">{tipo_alerta}&nbsp;&nbsp;</td>
                    <td style="padding:10px 13px">&nbsp;&nbsp;<b>Sectores:</b></td>
                    <td style="padding:10px 13px">{sectores}</td>
                  </tr>
                </table>
              </td>
            </tr>

            <!-- Threat Information -->
            <tr>
              <td style="background:rgb(4,70,102);color:#fff;padding:10px 13px;font-weight:bold">&nbsp;&nbsp;Threat Information</td>
            </tr>
            <tr>
              <td style="background:#fff;padding:10px 0">
                <table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse">
                  <tr>
                    <td style="padding:10px 13px;width:20%">&nbsp;&nbsp;<b>Número de IoCs:</b></td>
                    <td style="padding:10px 13px;width:30%">{numero_ioc}&nbsp;&nbsp;</td>
                    <td style="padding:10px 13px;width:20%">&nbsp;&nbsp;<b>PAP:</b></td>
                    <td style="padding:10px 13px;width:30%">{pap}</td>
                  </tr>
                  <tr>
                    <td style="padding:10px 13px">&nbsp;&nbsp;<b>Familia:</b></td>
                    <td style="padding:10px 13px">{familia}&nbsp;&nbsp;</td>
                    <td style="padding:10px 13px">&nbsp;&nbsp;<b>Adversario:</b></td>
                    <td style="padding:10px 13px">{adversary}</td>
                  </tr>
                </table>
              </td>
            </tr>

            <!-- Síntesis -->
            <tr>
              <td style="background:rgb(4,70,102);color:#fff;padding:10px 13px;font-weight:bold">&nbsp;&nbsp;Síntesis</td>
            </tr>
            <tr>
              <td style="background:#fff;padding:10px 20px;color:rgb(51,51,51);font-size:11pt">
                {sintesis}
              </td>
            </tr>

            <!-- TTPs -->
            <tr>
              <td style="background:rgb(4,70,102);color:#fff;padding:10px 13px;font-weight:bold">&nbsp;&nbsp;Técnicas y tácticas identificadas</td>
            </tr>
            <tr>
              <td style="background:#fff;padding:10px 20px;color:rgb(51,51,51);font-size:11pt">
                {tactics_html}
              </td>
            </tr>

            <!-- Mitigaciones -->
            <tr>
              <td style="background:rgb(4,70,102);color:#fff;padding:10px 13px;font-weight:bold">&nbsp;&nbsp;Mitigaciones</td>
            </tr>
            <tr>
              <td style="background:#fff;padding:10px 20px;color:rgb(51,51,51);font-size:11pt">
                <ul style="margin:0; padding-left:20px;">{mitigations_html}</ul>
              </td>
            </tr>

            <!-- Impacto y recomendaciones -->
            <tr>
              <td style="background:rgb(4,70,102);color:#fff;padding:10px 13px;font-weight:bold">&nbsp;&nbsp;Impacto y recomendaciones</td>
            </tr>
            <tr>
              <td style="background:#fff;padding:10px 20px;color:rgb(51,51,51);font-size:11pt">
                <ul style="margin:0; padding-left:20px;">{recs_html}</ul>
              </td>
            </tr>

            <!-- Referencias -->
            <tr>
              <td style="background:rgb(4,70,102);color:#fff;padding:10px 13px;font-weight:bold">&nbsp;&nbsp;Referencias</td>
            </tr>
            <tr>
              <td style="background:#fff;padding:10px 20px;color:rgb(51,51,51);font-size:11pt">
                <ul style="margin:0; padding-left:20px;">{refs_html}</ul>
              </td>
            </tr>

            <!-- IoCs -->
            <tr>
              <td style="background:rgb(4,70,102);color:#fff;padding:10px 13px;font-weight:bold">&nbsp;&nbsp;Indicadores de compromiso</td>
            </tr>
            <tr>
              <td style="background:#fff;padding:10px 20px;color:rgb(51,51,51);font-size:11pt">
                {iocs_info}
              </td>
            </tr>

            <!-- Firma -->
            <tr>
              <td style="background:#fff;padding:18px 13px;text-align:center">
                <div style="color:#161516">_______________________________________</div>
                <div style="margin-top:10px">
                  <img src="https://mnemo.com/wp-content/uploads/firma_CTI.png" width="90%" alt="Firma">
                </div>
              </td>
            </tr>

            <!-- Disclaimer -->
            <tr>
              <td style="background:rgb(205,205,204);padding:12px 20px;color:#000;font-size:9pt;line-height:1.3">
                <b style="color:rgb(250,83,35)">Disclaimer:</b> La información suministrada es fruto del análisis e investigación del equipo de Cyber Threat Intelligence, se debe tratar y gestionar según los criterios establecidos en el TLP. Tenga en cuenta la posibilidad de que algún indicador o dato pueda identificarse posteriormente como falso positivo o falso negativo.
                <div style="text-align:center;margin-top:8px">
                  <b>Si no es necesario, no imprimas este correo.</b>
                </div>
              </td>
            </tr>

          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
    """
    return html_content