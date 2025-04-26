import pwn
import parameters
import secret
import socket
import base64
import json

HOST = '0.0.0.0'
PORT = 12345
FIRSTRUN = True

class LCG:
    def __init__(self):
        self.state = secret.seed
        self.a = parameters.a
        self.c = parameters.c
        self.m = parameters.m

    def nextGeneration(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

    def genKeyXor(self, length):
        key = bytearray()
        for i in range(length):
            part = self.nextGeneration()
            key += ((part >> ((part.bit_length() - 8) if part.bit_length() > 8 else 0)) & 0xFF).to_bytes(1, 'big')
        return bytes(key)

    def encrypt(self, msg):
        return pwn.xor(msg.encode(), self.genKeyXor(len(msg)))
    
    def decrypt(self, encrypted_msg):
        return pwn.xor(encrypted_msg, self.genKeyXor(len(encrypted_msg))).decode()

def start_server():
    global FIRSTRUN
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"[*] Serveur en écoute sur {HOST}:{PORT}...")

    client_socket, client_address = server.accept()
    print(f"[+] Connexion établie depuis {client_address}")

    lcg = LCG()

    while True:
        command = input("Commande à envoyer ? ")
        encrypted_command = base64.b64encode(lcg.encrypt(command))
        
        if FIRSTRUN:
            FIRSTRUN = False
            json_command = json.dumps({"first": "false","cmd": encrypted_command.decode()})
            client_socket.send(json_command.encode())
        else:
            json_command = json.dumps({"first": "true","id": lcg.state,"cmd": encrypted_command.decode()})
            client_socket.send(json_command.encode())

        encrypted_response = client_socket.recv(4096)
        decrypted_response = lcg.decrypt(base64.b64decode(encrypted_response))
        print(f"{decrypted_response}")

    client_socket.close()
    print("[*] Connexion fermée.")

if __name__ == "__main__":
    start_server()