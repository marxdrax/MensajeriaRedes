import socket
import hashlib
import signal
import sys
import threading
from datetime import datetime
import traceback

# Configuración
MAX_LARGO_MENSAJE = 255
global running
running = True

PUERTO = int(sys.argv[1])

def crearSocketTCP():
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def crearSocketUDP():
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def emisorUDP(destino, mensaje):
    sock = crearSocketUDP()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.sendto(mensaje.encode(), (destino, PUERTO))
    sock.close()

def emisorTCP(destino, mensaje):
    sock = crearSocketTCP()
    sock.connect((destino, PUERTO))
    sock.send(mensaje.encode())
    sock.close()

def receptorTCP():
    sock = crearSocketTCP()
    sock.bind(("0.0.0.0", PUERTO))
    sock.listen(5)
    print(f"Escuchando en el puerto {PUERTO}")
    while running:
        conn, addr = sock.accept()
        with conn:
            while True:
                mensaje = conn.recv(1024).decode()
                if not mensaje:
                    break
                mensaje = mensaje.split(" ", 1)
                usuario = mensaje[0]
                mensaje = mensaje[1]
                print(f"[{datetime.now()}] {addr} {usuario} dice: {mensaje}")
            conn.close()

def receptorUDP():
    sock = crearSocketUDP()
    sock.bind(("0.0.0.0", PUERTO))
    print(f"Escuchando en el puerto {PUERTO}")
    while running:
        mensaje, direccion = sock.recvfrom(1024)
        mensaje = mensaje.decode()
        print(f"[{datetime.now()}] {direccion} dice: {mensaje}")
    sock.close()
                
def controladorEmisor(usuario):
    try:
        while running:
            mensaje = input().split(" ", 1)
            destino = mensaje[0]
            mensaje = mensaje[1][:MAX_LARGO_MENSAJE]
            mensaje_a_enviar = f"{usuario} {mensaje}"
            if destino == '*':
                emisorUDP('255.255.255.255', mensaje_a_enviar)
            else:
                emisorTCP(destino, mensaje_a_enviar)
    except Exception as e:
        print(f"Error en el controlador del emisor: {e}")
        traceback.print_exc()

def cierre():
    global running
    running = False
    sys.exit(0)

def signal_handler(signum, frame):
    print(f"\nRecibi la senal {signum}. Cerrando")
    cierre()

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == "__main__":
    try:
        usuario = input("Usuario: ")
        password = hashlib.md5(usuario.encode()).hexdigest()
        hiloReceptorTCP = threading.Thread(target=receptorTCP, daemon= False)
        hiloReceptorUDP = threading.Thread(target=receptorUDP, daemon= False)
        hiloEmisor = threading.Thread(target=controladorEmisor, args=(usuario,), daemon= False)
        hiloReceptorTCP.start()
        hiloReceptorUDP.start()
        hiloEmisor.start()

        while running:
            pass
    except KeyboardInterrupt:
        hiloEmisor.join()
        hiloReceptorTCP.join()
        hiloReceptorUDP.join()
        cierre()
        

    #conectar al server de auth
    #auth = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #auth.connect(("localhost", 8080))
    #auth.sendall(f"{usuario} {password}".encode())
    #auth.close()

    


