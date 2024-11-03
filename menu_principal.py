import os
import subprocess
import argparse
import platform
import hashlib
from datetime import datetime

os_name = platform.system()

# Establecer la ruta a la carpeta donde están los scripts
script_path = os.path.dirname(os.path.abspath(__file__))

# Función para ejecutar scripts de PowerShell
def run_powershell_script(script_name):
    script = os.path.join(script_path, script_name)
    subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", script], check=True)

# Función para ejecutar scripts de Python
def run_python_script(script_name):
    os_name = platform.system()
    script = os.path.join(script_path, script_name)
    if os_name == "Windows":
        subprocess.run(["python", script], check=True)
    elif os_name == "Linux":
        subprocess.run(["python3", script], check=True)

# Función para ejecutar scripts de Bash
def run_bash_script(script_name):
    script = os.path.join(script_path, script_name)
    subprocess.run(["bash", script], check=True)

def execute_module(option):
    windows_commands = {
        1: "API_IPABUSE.py",
        2: "Complejo.py",
        3: "deteccion.py",
        4: "trafico.py",
        5: "API_Shodan.py",
        6: "ListadoDeArchivosOcultos.ps1",
        7: "Modulo_UsoRecursos.ps1",
        8: "virus.ps1",
    }

    linux_commands = {
        1: "API_IPABUSE.py",
        2: "Complejo.py",
        3: "deteccion.py",
        4: "trafico.py",
        5: "API_Shodan.py",
        6: "escaneo_puertos.sh",
        7: "Monitoreo_Red.sh",
    }

    commands = windows_commands if os_name == "Windows" else linux_commands

    if 1 <= option <= len(commands):
        script_name = commands.get(option)
        script_path_full = os.path.join(script_path, script_name)

        print(f"Ruta completa del script: {script_path_full}")  # Depuración

        if os.path.exists(script_path_full):
            try:
                print(f"Ejecutando: {script_name}")
                # Determinamos el tipo de script y ejecutamos la función correspondiente
                if script_name.endswith('.py'):
                    run_python_script(script_name)
                    reporte(script_name)
                elif script_name.endswith('.ps1'):
                    run_powershell_script(script_name)
                    reporte(script_name)
                elif script_name.endswith('.sh'):
                    run_bash_script(script_name)
                    reporte(script_name)
                else:
                    print("Tipo de script no soportado.")
            except subprocess.CalledProcessError as e:
                print(f"Error al ejecutar {script_name}: {e}")
            except Exception as e:
                print(f"Ocurrió un error inesperado: {e}")
        else:
            print(f"El archivo no existe o no es compatible con el sistema operativo {os_name}: {script_path_full}")
    else:
        print("Opción no válida. Debe ser un número entre 1 y", len(commands))

def reporte(x):
    script_path = os.path.dirname(os.path.abspath(__file__))
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"tarea '{x}' ejecutada el {fecha}")
    print(f"ubicacion del archivo: {script_path}")

def show_menu():
    if os_name == "Windows":
        print("Seleccione una opción para Windows:")
        print("1: API_IPABUSE.py - Utiliza la API de IPAbuse para verificar y reportar IPs.")
        print("2: Complejo.py - Encripta y desencripta mensajes.")
        print("3: deteccion.py - Realiza un ataque de fuerza bruta a un servidor SSH.")
        print("4: trafico.py - Analiza el tráfico de red.")
        print("5: API_Shodan.py - Utiliza la API de Shodan para obtener información de una IP.")
        print("6: ListadoDeArchivosOcultos.ps1 - Muestra una lista de archivos ocultos en el sistema.")
        print("7: Modulo_UsoRecursos.ps1 - Monitorea el uso de recursos del sistema.")
        print("8: virus.ps1 - Utiliza la API de VirusTotal para comparar los hash de una lista de archivos.")
        print("0: Salir - Cierra el programa.")
    elif os_name == "Linux":
        print("Seleccione una opción para Linux:")
        print("1: API_IPABUSE.py - Utiliza la API de IPAbuse para verificar y reportar IPs.")
        print("2: Complejo.py - Encripta y desencripta mensajes.")
        print("3: deteccion.py - Realiza un ataque de fuerza bruta a un servidor SSH.")
        print("4: trafico.py - Analiza el tráfico de red.")
        print("5: API_Shodan.py - Utiliza la API de Shodan para obtener información de una IP.")
        print("6: escaneo_puertos.sh - Escanea puertos de una IP.")
        print("7: Monitoreo_Red.sh - Realiza monitoreo de tráfico de red.")
        print("0: Salir - Cierra el programa.")

def main():
    # Comentarios de uso
    """
    Este script ejecuta diferentes scripts de Python, PowerShell y Bash según la opción elegida.

    Uso:
        -o OPCION : Especifica el número del script a ejecutar (1-10).
        -i : Muestra información sobre el script seleccionado.
        -r : Genera un reporte de ejecución.

    Ejemplo:
        python menu_principal.py -h # Muestra informacion del menu principal.
        python prueba.py -o 1     # Ejecuta el script 1.
        python prueba.py -o 2 -i  # Muestra información sobre el script 2.
        python menu_principal.py -o 2 -i -r # Genera un reporte de el script 2.
        
    """

    # Diccionario de descripciones de los scripts
    script_descriptions = {
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
    }

    
    
    # Configuración de argparse
    parser = argparse.ArgumentParser(description='Script de ejecución de módulos.')
    parser.add_argument('-o', '--option', type=int, help='Número de la opción deseada (1-10)', required=False)
    parser.add_argument('-i', '--info', type=int, choices=range(1, 11), help='Muestra información sobre el script seleccionado (1-10).')
    parser.add_argument('-r', '--report', action='store_true', help='Genera un reporte de ejecución.')

    args = parser.parse_args()

    # Mostrar la información del script seleccionado si se usa el argumento -i
    if args.info:
        print(f"Información sobre el script {args.info}: {script_descriptions.get(args.info)}")
        return

    # Si se pasa una opción por argumentos, ejecuta esa opción
    if args.option is not None:
        if args.info:
            print(f"Información sobre la opción {args.option}: {args.option} - {commands.get(args.option)}")
        execute_module(args.option)
    else:
        # Muestra el menú y solicita la opción si no se pasa como argumento
        while True:
            show_menu()
            try:
                option = int(input("Ingrese el número de la opción deseada: "))
                if option == 0:
                    print("Saliendo del programa...")
                    break
                execute_module(option)
            except ValueError:
                print("Por favor, ingrese un número válido.")  # Manejo de errores de entrada
            except Exception as e:
                print(f"Ocurrió un error: {e}")

if __name__ == "__main__":
    main()
