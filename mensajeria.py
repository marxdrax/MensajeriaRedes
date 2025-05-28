import socket
import threading
import sys
import os
import hashlib
import signal
import time
from datetime import datetime

MAX_LARGO_MENSAJE = 255

# Variables globales
USUARIO = ""
MI_IP = socket.gethostbyname(socket.gethostname())
PUERTO_LOCAL = 0
PUERTO_AUTH = 0
IP_AUTH = ""
PUERTO_DESTINO = 0
SOCKETS_ABIERTOS = []

# === Autenticación ===
def codificar_md5(texto):
    return hashlib.md5(texto.encode()).hexdigest()

def autenticar(usuario, clave, ip_auth, puerto_auth):
    clave_md5 = codificar_md5(clave)
    credencial = f"{usuario}-{clave_md5}\r\n"  # Asegura CRLF

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)  # Timeout mayor para esperar el nombre
        s.connect((ip_auth, puerto_auth))
        
        # 1. Recibir bienvenida inicial
        bienvenida = s.recv(1024).decode().strip()
        print(bienvenida)  # Muestra inmediatamente "Redes 2025 - Laboratorio..."
        
        # 2. Enviar credenciales
        s.sendall(credencial.encode())
        
        # 3. Recibir SI/NO (primera respuesta)
        respuesta = s.recv(4).decode().strip()  # "SI\r\n" o "NO\r\n" son 4 bytes
        
        if respuesta == "SI":
            nombre = s.recv(1024).decode().strip()
            return True, nombre
        else:
            return False, ""
            
    except Exception as e:
        print(f"[ERROR] Autenticación fallida: {e}")
        return False, ""
    finally:
        s.close()

# === Receptores ===
def receptor_tcp(puerto):
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    SOCKETS_ABIERTOS.append(servidor)
    servidor.bind(('', puerto))
    servidor.listen()
    print(f"[INFO] Receptor TCP escuchando en puerto {puerto}...")

    while True:
        conn, addr = servidor.accept()
        threading.Thread(target=manejar_tcp, args=(conn, addr)).start()

def manejar_tcp(conn, addr):
    try:
        datos = conn.recv(1024).decode()
        ahora = datetime.now().strftime("[%Y.%m.%d %H:%M]")

        if datos.startswith("$file"):
            # Separa el nombre del archivo
            nombre_archivo = datos.split(" ", 1)[1].strip()
            
            # Prepara para recibir los datos del archivo
            with open(nombre_archivo, "wb") as f:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    f.write(data)
            
            print(f"{ahora} {addr[0]} <Recibido ./{nombre_archivo} de {USUARIO}>")
        else:
            print(f"{ahora} {datos}")
    except Exception as e:
        print(f"{ahora} {addr[0]} <Error recibiendo archivo: {str(e)}>")
    finally:
        conn.close()

def receptor_broadcast(puerto):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    SOCKETS_ABIERTOS.append(sock)
    sock.bind(('', puerto))
    print(f"[INFO] Receptor UDP (Broadcast) escuchando en puerto {puerto}...")

    while True:
        data, addr = sock.recvfrom(1024)
        ahora = datetime.now().strftime("[%Y.%m.%d %H:%M]")
        print(f"{ahora} {addr[0]} {data.decode()}")

# === Emisor ===
def emisor():
    while True:
        entrada = input()
        if not entrada.strip():
            continue

        partes = entrada.split(" ", 1)
        destino = partes[0]
        contenido = partes[1] if len(partes) > 1 else ""

        if contenido.startswith("&file"):
            ruta = contenido.split(" ", 1)[1]
            enviar_archivo(destino, ruta)
        else:
            enviar_mensaje(destino, contenido)
                
def enviar_mensaje(destino, mensaje):
    # Separar IP y puerto si se usa "IP:PUERTO"
    if ":" in destino:
        ip_destino, puerto_destino_str = destino.split(":")
        puerto_destino = int(puerto_destino_str)
    else:
        ip_destino = destino
        puerto_destino = PUERTO_DESTINO  # Usa el puerto por defecto

    mensaje_formateado = f"{MI_IP} {USUARIO} dice: {mensaje}"

    if ip_destino == "*":  # Broadcast
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(mensaje_formateado.encode(), ("255.255.255.255", puerto_destino))
    else:  # Mensaje directo (TCP)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:


            try:
                ip_destino_resuelto = socket.gethostbyname(ip_destino)  # Resuelve DNS si es necesario
                s.connect((ip_destino_resuelto, puerto_destino))
                s.sendall(mensaje_formateado.encode())
            except Exception as e:
                print(f"[ERROR] No se pudo enviar mensaje a {destino}: {e}")


def enviar_archivo(destino, path):
    if not os.path.isfile(path):
        print(f"[ERROR] Archivo {path} no encontrado.")
        return

    if destino == "*":
        print("[ERROR] No se puede hacer broadcast de archivos.")
        return

    # Separa IP y puerto si es necesario
    if ":" in destino:
        ip_destino, puerto_destino_str = destino.split(":")
        puerto_destino = int(puerto_destino_str)
    else:
        ip_destino = destino
        puerto_destino = PUERTO_DESTINO

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            ip_destino_resuelto = socket.gethostbyname(ip_destino)
            s.connect((ip_destino_resuelto, puerto_destino))
            
            # Primero envía el comando con el nombre del archivo
            s.sendall(f"$file {os.path.basename(path)}".encode())
            
            # Luego envía el contenido del archivo
            with open(path, "rb") as f:
                while True:
                    bytes_leidos = f.read(4096)
                    if not bytes_leidos:
                        break
                    s.sendall(bytes_leidos)
            
            # Espera un momento para asegurar que todo se envió
            time.sleep(0.1)
            
        except Exception as e:
            print(f"[ERROR] No se pudo enviar archivo a {destino}: {e}")

# === Manejador de señales ===
def cerrar_programa(signal_num, frame):
    print("\n[INFO] CTRL + C Recibido.... Cerrando sesión")
    for s in SOCKETS_ABIERTOS:
        try:
            s.close()
        except:
            pass
    sys.exit(0)

signal.signal(signal.SIGINT, cerrar_programa)

# === Main ===
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python3 mensajeria.py <puerto> <ipAuth> <puertoAuth>")
        sys.exit(1)

    PUERTO_LOCAL = int(sys.argv[1])
    IP_AUTH = sys.argv[2]
    PUERTO_AUTH = int(sys.argv[3])
    PUERTO_DESTINO = PUERTO_LOCAL

    # Autenticación
    USUARIO = input("Usuario: ")
    CLAVE = input("Clave: ")
    ok, nombre = autenticar(USUARIO, CLAVE, IP_AUTH, PUERTO_AUTH)
    if not ok:
        print("[ERROR] Autenticación fallida.")
        sys.exit(1)

    print(f"Bienvenido {nombre}")

    # Lanzar hilos receptores
    threading.Thread(target=receptor_tcp, args=(PUERTO_LOCAL,), daemon=True).start()
    threading.Thread(target=receptor_broadcast, args=(PUERTO_LOCAL,), daemon=True).start()

    # Iniciar emisor
    emisor()