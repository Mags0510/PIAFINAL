# Proyecto de Ejecución de Scripts Multiplataforma
#nuestra documentacion 
Este proyecto permite ejecutar diversos scripts en Python, PowerShell y Bash desde una misma interfaz en Python. Ideal para tareas automatizadas en Windows y Linux.

## Scripts incluidos

        1: "API_IPABUSE.py - Utiliza la API de IPAbuse para verificar y reportar IPs.",
        2: "Complejo.py - Encripta y desencripta mensajes.",
        3: "deteccion.py - Realiza un ataque de fuerza bruta a un servidor SSH.",
        4: "escaneo_puertos.sh - Escanea puertos de una IP.",
        5: "ListadoDeArchivosOcultos.ps1 - Muestra una lista de archivos ocultos en el sistema.",
        6: "Modulo_UsoRecursos.ps1 - Monitorea el uso de recursos del sistema.",
        7: "Monitoreo_Red.sh - Realiza monitoreo de tráfico de red.",
        8: "trafico.py - Analiza el tráfico de red.",
        9: "virus.ps1 - Utiliza la API de VirusTotal para comparar los hash de una lista de archivos.",
        10: "API_Shodan.py - Utiliza la API de Shodan para obtener información de una IP."

#usted puede de esta manera instalar el repositorio 

1. Clona este repositorio:
    ```bash
    git clone https://github.com/usuario/proyecto.git
    cd proyecto
    ```
2. Asegúrate de tener los permisos necesarios para ejecutar scripts:
    - En Windows: habilitar la política de ejecución para PowerShell (`Set-ExecutionPolicy Bypass -Scope Process`).
    - En Linux: dar permisos de ejecución a los scripts Bash (`chmod +x nombre_script.sh`).

## Uso

desde la consola
en PowerShell:
python menu_principal.py -o <opción>
tambien lo puedes ejecutar dando doble click en el, solo asegurate que este en la misma carpeta que los modulos

en Bash:
python3 menu_principal.py -o <opción>
