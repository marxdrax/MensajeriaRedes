import socket
import hashlib
import signal
import sys
import time
import threading

#Configuracion
MAX_LARGO_MENSAJE = 255
HOST = "0.0.0.0"

#Control de salida por ctrl c
def manejar_salida(sig, frame):
    print("\nCTRL + C recibido. Cerrando programa correctamente...")
    sys.exit(0)  # Finaliza el programa limpiamente

# Configurar el manejador de señales
signal.signal(signal.SIGINT, manejar_salida)
#_____________________________________________________________________

def receptor(usuario):
    #crear socket para escuchar sobre el puerto pasado en sys.argv[1] (por consola al ejecutar el programa)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, int(sys.argv[1]))) #host 0.0.0.0 para escuchar todas las interfaces de red segun chatgpt, sys.argv[1] es el puerto definido en el argumento pasado al ejecutar el programa
    server_socket.listen(5) #maximo de conexiones aceptadas en simultaneo

    while True:
        client_socket, client_address = server_socket.accept()
        ip_emisor = client_address[0] #se usa client_address[0] dado que es una tupla adr:port

        msg = client_socket.recv(MAX_LARGO_MENSAJE).decode('utf-8').strip() #recibe mensajes de maximo 255 bits, se deberia contemplar caso de mas, para ignorarlos, cortarlos o solicitar se reenvie ajustado al largo
        hora = time.strftime("%Y.%m.%d %H:%M")
        print(f"[{hora}] {ip_emisor} {usuario} dice: {msg}")
        client_socket.close()




def emisor():
   #crear socket para enviar mensajes a partir de un ingreso desde terminal, una vez ejecutado el programa, por el usuario


def auth():
    #socket para conectar al servidor de auth en ti.esi.edu.uy:33, donde se enviara el usuario y la password generados en el main (se pueden pasar a este metodo), y obtener la respuesta SI o NO por dicha app


if __name__ == "__main__":
    while True:
        usuario = input("Usuario: ")
        password = hashlib.md5(usuario.encode()).hexdigest() #se encripta la password en md5
        auth() #ejecutar la consulta con el usuario y la password al server de auth
        if auth() == "SI":
            print(f"Bienvenido {nombreCompleto}")#nombreCompleto viene en la respuesta del server de auth
            #se ubica aqui la creacion de los hilos de recep y emisor para hacerlo solo una vez se autentique el usuario
            hilo_receptor = threading.Thread(target=receptor)
            hilo_emisor = threading.Thread(target=emisor)
            hilo_receptor.start()
            hilo_emisor.start()

            hilo_receptor.join()
            hilo_emisor.join()
        else:
            print("Error de autenticacion")
        
        
        
        