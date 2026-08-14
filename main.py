import os
from modules.mitre_mapper import get_mitre_software_info
from modules.html_generator import generate_html_alert
from modules.pdf_generator import generate_pdf_report
from modules.notifier import send_alert_email

def main():
    print("=" * 60)
    print(" 🛡️ CTI ALERT & REPORT GENERATOR - MNEMO SOC 🛡️ ")
    print("=" * 60)
    
    print("\nSelecciona el método de entrada para la alerta:")
    print("1. Consultar por nombre de Software / Amenaza (ej. Ransomware, APT, etc.)")
    print("2. Ingresar resumen de incidente manualmente por texto")
    
    opcion = input("\nIntroduce tu opción (1 o 2): ").strip()
    
    if opcion == '1':
        software_name = input("🔍 Introduce el nombre del software o amenaza: ").strip()
        if not software_name:
            print("❌ El nombre no puede estar vacío.")
            return
        # Obtener estructura desde el mapeador de MITRE
        report_data = get_mitre_software_info(software_name)
        
    elif opcion == '2':
        print("\n📝 Ingresa los detalles del incidente manualmente:")
        title = input("Título de la alerta: ").strip()
        description = input("Descripción general / Resumen: ").strip()
        
        # Estructura personalizada manual
        report_data = {
            "title": f"Alerta CTI: {title}",
            "threat_name": title,
            "description": description,
            "tactics": [
                {
                    "tactic": "Initial Access / Execution",
                    "id": "TA0001/TA0002",
                    "techniques": [
                        {"id": "T1566", "name": "Phishing / Custom Entry", "description": "Vector reportado manualmente por el analista SOC."}
                    ]
                }
            ],
            "recommendations": [
                "Bloquear dominios/IPs maliciosos asociados.",
                "Aplicar revisión exhaustiva en endpoints críticos.",
                "Actualizar reglas de detección en el SIEM."
            ]
        }
    else:
        print("❌ Opción no válida.")
        return

    print("\n🔄 Generando formatos de salida (HTML y PDF)...")
    
    # 1. Generar contenido HTML
    html_content = generate_html_alert(report_data)
    html_filename = "reporte_alerta.html"
    with open(html_filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"🌐 Archivo HTML generado con éxito: {html_filename}")

    # 2. Generar reporte PDF
    pdf_filename = generate_pdf_report(report_data, "reporte_alerta_cti.pdf")

    # 3. Preguntar si se desea enviar por correo a los clientes
    enviar = input("\n📧 ¿Deseas enviar esta alerta por correo a los clientes configurados? (s/n): ").strip().lower()
    if enviar == 's':
        subject = f"[{report_data.get('threat_name', 'SOC').upper()}] Alerta de Ciberinteligencia - MNEMO"
        send_alert_email(subject, html_content, pdf_filename)
    else:
        print("\n✨ Proceso finalizado localmente sin envío de correo.")

if __name__ == "__main__":
    main()