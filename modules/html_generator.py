from datetime import datetime

def generate_html_alert(data):
    """
    Genera el contenido HTML estructurado para la alerta CTI utilizando la plantilla oficial de MNEMO.
    """
    # Obtener valores con respaldos predeterminados si faltan en el diccionario
    titulo = data.get('title', 'Cyber Security Warning')
    fecha = data.get('date', datetime.now().strftime('%Y-%m-%d %H:%M'))
    tlp = data.get('tlp', 'TLP:AMBER')
    cve = data.get('cve', 'N/A')
    cvss = data.get('cvss', 'N/A')
    vector = data.get('vector', 'Red/Endpoint')
    control = data.get('control', 'Pendiente')
    
    # Descripción
    descripcion = data.get('description', 'Sin descripción disponible.')
    
    # Productos afectados
    productos_list = data.get('affected_products', ['Sistemas y software genéricos asociados a la amenaza.'])
    productos_html = "".join([f"<li>{prod}</li>" for prod in productos_list])
    
    # Referencias MITRE / TTPs
    tactics_html = ""
    for tactic in data.get("tactics", []):
        tech_items = ""
        for tech in ttp_item := tactic.get("techniques", []):
            tech_items += f"<li><b>{tech_item['id']} - {tech_item['name']}</b>: {tech_item['description']}</li>" if isinstance(tech_item, dict) else f"<li>{tech_item}</li>"
        
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

    # Mitigaciones ATT&CK
    mitigations_list = data.get('mitigations', [
        "Monitorear indicadores de compromiso (IoCs) en el perímetro.",
        "Aplicar políticas de restricción de ejecución en endpoints."
    ])
    mitigations_html = "".join([f"<li>{mit}</li>" for mit in mitigations_list])

    # Recomendaciones
    recs_list = data.get('recommendations', [
        "Actualizar los sistemas afectados a los parches de seguridad más recientes.",
        "Revisar los registros del SIEM ante patrones de comportamiento similares."
    ])
    recs_html = "".join([f"<li>{rec}</li>" for rec in recs_list])

    # Referencias generales
    refs_list = data.get('references', [
        "https://attack.mitre.org/",
        "https://cve.mitre.org/"
    ])
    refs_html = "".join([f'<li><a href="{ref}" target="_blank" style="color: #3498db;">{ref}</a></li>' for ref in refs_list])

    # Estructura de la plantilla HTML oficial integrada
    html_content = f"""
<!DOCTYPE html>
<html lang="es">
  <body style="margin:0;background:rgb(238,238,238)">
    <table width="100%" align="center" cellpadding="0" cellspacing="0" border="0" style="background:rgb(238,238,238);margin:0;padding:10px 0">
      <tr>
        <td align="center">
          <div>
            <table width="70%" align="center" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto;font-family:Arial,sans-serif;border-collapse:collapse;background:rgb(246,247,246)">
              <tr>
                <td valign="top" align="center" style="background:rgb(246,247,246)">
                  <img src="https://mnemo.com/wp-content/uploads/header_CTI-scaled.png" width="100%" alt="Header">
                </td>
              </tr>

              <tr>
                <td colspan="2" style="background:rgb(250,83,35);color:#fff;padding:12px 20px;font-weight:bold">
                  <span style="font-size:15pt">Cyber Security Warning - Early</span>
                </td>
              </tr>

              <tr>
                <td>
                  <div style="background:rgb(246,247,246)">
                    <table width="100%" align="center" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto;border-collapse:collapse;background:#fff">
                      <tr>
                        <td style="border-bottom:1px solid rgb(224,225,227);padding:12px 10px 12px 15px">
                          <span style="color:rgb(51,51,51);font-size:13pt;font-weight:bold">{titulo}</span>
                        </td>
                      </tr>
                    </table>
                  </div>
                </td>
              </tr>

              <tr>
                <td>
                  <div style="background:rgb(246,247,246)">
                    <table width="100%" align="center" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto;border-collapse:collapse;background:#fff">
                      <tr>
                        <td colspan="2" style="padding:10px 13px;width:20%">
                          <span style="color:#000;font-size:12pt"><b>FECHA:</b></span>
                        </td>
                        <td colspan="2" style="padding:10px 13px;width:40%">
                          <span style="color:#000;font-size:12pt">{fecha}</span>
                        </td>
                        <td colspan="2" style="padding:10px 13px;width:20%">
                          <span style="color:#000;font-size:12pt"><b>TLP:</b></span>
                        </td>
                        <td colspan="2" style="padding:10px 13px;width:20%">
                          <span style="color:#000;font-size:12pt">{tlp}</span>
                        </td>
                      </tr>

                      <tr>
                        <td colspan="2" style="padding:10px 13px;width:20%">
                          <span style="color:#000;font-size:12pt"><b>Número de CVE:</b></span>
                        </td>
                        <td colspan="2" style="padding:10px 13px;width:40%">
                          <span style="color:#000;font-size:12pt">{cve}</span>
                        </td>
                        <td colspan="2" style="padding:10px 13px;width:20%">
                          <span style="color:#000;font-size:12pt"><b>Top CVSS:</b></span>
                        </td>
                        <td colspan="2" style="padding:10px 13px;width:20%">
                          <span style="color:#000;font-size:12pt">{cvss}</span>
                        </td>
                      </tr>

                      <tr>
                        <td colspan="2" style="padding:10px 13px;width:20%">
                          <span style="color:#000;font-size:12pt"><b>Vector de ataque:</b></span>
                        </td>
                        <td colspan="2" style="padding:10px 13px;width:40%">
                          <span style="color:#000;font-size:12pt">{vector}</span>
                        </td>
                        <td colspan="2" style="padding:10px 13px;width:20%">
                          <span style="color:#000;font-size:12pt"><b>Control comp:</b></span>
                        </td>
                        <td colspan="2" style="padding:10px 13px;width:20%">
                          <span style="color:#000;font-size:12pt">{control}</span>
                        </td>
                      </tr>
                    </table>
                  </div>
                </td>
              </tr>

              <tr>
                <td colspan="2" style="background:rgb(73,74,79);color:#fff;padding:10px 13px;font-weight:bold"> Descripción</td>
              </tr>
              <tr>
                <td>
                  <div style="background:rgb(246,247,246)">
                    <table width="100%" align="center" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto;border-collapse:collapse;background:#fff">
                      <tr>
                        <td style="padding:10px 20px">
                          <span style="color:rgb(51,51,51);font-size:11pt">{descripcion}</span>
                        </td>
                      </tr>
                    </table>
                  </div>
                </td>
              </tr>

              <tr>
                <td colspan="2" style="background:rgb(73,74,79);color:#fff;padding:10px 13px;font-weight:bold"> Productos afectados</td>
              </tr>
              <tr>
                <td>
                  <div style="background:rgb(246,247,246)">
                    <table width="100%" align="center" cellpadding="10" cellspacing="0" border="0" style="margin:0 auto;border-collapse:collapse;background:#fff">
                      <tr>
                        <td style="padding:10px 20px">
                          <span style="color:rgb(51,51,51);font-size:11pt">
                            <ul style="margin:0; padding-left:20px;">{productos_html}</ul>
                          </span>
                        </td>
                      </tr>
                    </table>
                  </div>
                </td>
              </tr>

              <tr>
                <td colspan="2" style="background:rgb(73,74,79);color:#fff;padding:10px 13px;font-weight:bold"> Referencias Mitre</td>
              </tr>
              <tr>
                <td>
                  <div style="background:rgb(246,247,246)">
                    <table width="100%" align="center" cellpadding="10" cellspacing="0" border="0" style="margin:0 auto;border-collapse:collapse;background:#fff">
                      <tr>
                        <td style="padding:10px 20px">
                          <span style="color:rgb(51,51,51);font-size:11pt">{tactics_html}</span>
                        </td>
                      </tr>
                    </table>
                  </div>
                </td>
              </tr>

              <tr>
                <td colspan="2" style="background:rgb(73,74,79);color:#fff;padding:10px 13px;font-weight:bold"> Mitigaciones ATT&CK</td>
              </tr>
              <tr>
                <td>
                  <div style="background:rgb(246,247,246)">
                    <table width="100%" align="center" cellpadding="10" cellspacing="0" border="0" style="margin:0 auto;border-collapse:collapse;background:#fff">
                      <tr>
                        <td style="padding:10px 20px">
                          <span style="color:rgb(51,51,51);font-size:11pt">
                            <ul style="margin:0; padding-left:20px;">{mitigations_html}</ul>
                          </span>
                        </td>
                      </tr>
                    </table>
                  </div>
                </td>
              </tr>

              <tr>
                <td colspan="2" style="background:rgb(73,74,79);color:#fff;padding:10px 13px;font-weight:bold"> Recomendaciones</td>
              </tr>
              <tr>
                <td>
                  <div style="background:rgb(246,247,246)">
                    <table width="100%" align="center" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto;border-collapse:collapse;background:#fff">
                      <tr>
                        <td style="padding:10px 20px">
                          <span style="color:rgb(51,51,51);font-size:11pt">
                            <ul style="margin:0; padding-left:20px;">{recs_html}</ul>
                          </span>
                        </td>
                      </tr>
                    </table>
                  </div>
                </td>
              </tr>

              <tr>
                <td colspan="2" style="background:rgb(73,74,79);color:#fff;padding:10px 13px;font-weight:bold"> Referencias</td>
              </tr>
              <tr>
                <td>
                  <div style="background:rgb(246,247,246)">
                    <table width="100%" align="center" cellpadding="10" cellspacing="0" border="0" style="margin:0 auto;border-collapse:collapse;background:#fff">
                      <tr>
                        <td style="padding:10px 20px">
                          <span style="color:rgb(51,51,51);font-size:11pt">
                            <ul style="margin:0; padding-left:20px;">{refs_html}</ul>
                          </span>
                        </td>
                      </tr>
                    </table>
                  </div>
                </td>
              </tr>

              <tr>
                <td>
                  <div style="background:rgb(246,247,246)">
                    <table width="100%" align="center" cellpadding="0" cellspacing="0" border="0" style="margin:0 auto;border-collapse:collapse;background:#fff">
                      <tr>
                        <td colspan="2" style="padding:10px 13px;width:50%;text-align:center">
                          <div style="color:#161516">_______________________________________</div>
                          <p style="margin:10px 0 0">
                            <img src="https://mnemo.com/wp-content/uploads/firma_CTI.png" width="90%" alt="Firma">
                          </p>
                        </td>
                      </tr>
                    </table>
                  </div>
                </td>
              </tr>

              <tr>
                <td>
                  <div style="background:rgb(246,247,246)">
                    <table width="100%" align="center" cellpadding="10" cellspacing="0" border="0" style="margin:0 auto;border-collapse:collapse;background:rgb(205,205,204)">
                      <tr>
                        <td style="padding:12px 20px">
                          <span style="color:rgb(250,83,35);font-size:9pt"><b>Disclaimer:</b></span>
                          <span style="color:#000;font-size:9pt">
                            La información suministrada es fruto del análisis e investigación del equipo de Cyber Threat Intelligence, se debe tratar y gestionar según los criterios establecidos en el TLP. Tenga en cuenta la posibilidad de que algún indicador o dato pueda identificarse posteriormente como falso positivo o falso negativo.
                          </span>
                          <div style="text-align:center;margin-top:8px">
                            <b><span style="color:#000;font-size:9pt">Si no es necesario, no imprimas este correo.</span></b>
                          </div>
                        </td>
                      </tr>
                    </table>
                  </div>
                </td>
              </tr>

            </table>
          </div>
        </td>
      </tr>
    </table>
  </body>
</html>
    """
    return html_content