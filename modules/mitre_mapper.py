import requests

def get_mitre_software_info(software_name):
    """
    Consulta información sobre un software/malware o técnica y genera un resumen estructurado 
    para las alertas del SOC, utilizando la API pública o fuentes estandarizadas de MITRE.
    """
    print(f"\n🔍 Buscando información sobre '{software_name}' en el contexto de MITRE ATT&CK...")
    
    # Aquí puedes integrar la consulta a la API oficial de MITRE ATT&CK STIX/TAXII o una búsqueda estructurada.
    # Como estructura base para tu generador de alertas, simularemos y estructuraremos la respuesta de ejemplo:
    
    # Estructura estandarizada requerida para el reporte HTML y PDF
    report_data = {
        "title": f情报 Alerta CTI: Análisis de {software_name.capitalize()}",
        "threat_name": software_name.capitalize(),
        "description": f"Se ha detectado actividad reciente o vectores de ataque asociados al software/amenaza {software_name}. Este componente interactúa con múltiples tácticas del framework MITRE ATT&CK.",
        "tactics": [
            {
                "tactic": "Execution",
                "id": "TA0002",
                "techniques": [
                    {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell", "description": "Uso de scripts maliciosos para ejecución de comandos."},
                    {"id": "T1204.002", "name": "User Execution: Malicious File", "description": "Engaño al usuario para abrir archivos adjuntos o ejecutables."}
                ]
            },
            {
                "tactic": "Defense Evasion",
                "id": "TA0005",
                "techniques": [
                    {"id": "T1027", "name": "Obfuscated Files or Information", "description": "Ofuscación de código para evitar la detección por firmas tradicionales."}
                ]
            }
        ],
        "recommendations": [
            "Revisar y bloquear indicadores de compromiso (IoCs) asociados en los firewalls y pasarelas de correo.",
            "Monitorear la ejecución de procesos hijos inusuales provenientes de intérpretes de comandos.",
            "Asegurar la integridad de los endpoints mediante aislamiento temporal en caso de sospecha."
        ]
    }
    
    return report_data