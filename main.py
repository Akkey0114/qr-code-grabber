# Import
import threading
import schedule
import hashlib
import qrcode
import base64
import httpx
import json
import time
import sys
import os

# From Import
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from websocket import WebSocket

class RemoteAuthClient:
    def __init__(self):
        # Crypt
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.public_key_string = "".join(self.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf8").split("\n")[1:-2])

        # Other
        self.ws = None
        self.closed = False

    def toggle_closed(self):
        self.closed = True
        print("Timed Out")

    def get_encrypted_token(self, ticket):
        response = httpx.post(
            "https://discord.com/api/v9/users/@me/remote-auth/login",
            headers = {
                "Content-Type": "application/json"
            },
            json = {
                "ticket": ticket
            }
        )
        return response.json()["encrypted_token"]

    def get_response(self):
        response = self.ws.recv()
        return json.loads(response)

    def send_request(self, payload):
        self.ws.send(json.dumps(payload))

    def heartbeat(self, interval):
        while not self.closed:
            time.sleep(interval)
            if self.closed:
                break
            self.send_request({"op": "heartbeat"})

    def main(self):
        print("Connecting...")
        self.ws = WebSocket()
        self.ws.connect("wss://remote-auth-gateway.discord.gg/?v=2", origin="https://discord.com")

        schedule.every(2).minutes.do(self.toggle_closed)

        while not self.closed:
            schedule.run_pending()
            try:
                response = self.get_response()

                if response["op"] == "hello":
                    print("Connected")
                    self.send_request({"op": "init", "encoded_public_key": self.public_key_string})
                    threading.Thread(target=self.heartbeat, args=(response["heartbeat_interval"] / 1000,)).start()
                elif response["op"] == "nonce_proof":
                    nonce_hash = hashlib.sha256()
                    nonce_hash.update(self.private_key.decrypt(base64.b64decode(bytes(response["encrypted_nonce"], "utf8")), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))
                    nonce_hash = base64.urlsafe_b64encode(nonce_hash.digest()).decode("utf8")
                    nonce_hash = nonce_hash.replace("/", "").replace("+", "").replace("=", "")
                    self.send_request({"op": "nonce_proof", "proof": nonce_hash})
                elif response["op"] == "pending_remote_init":
                    fingerprint = response["fingerprint"]
                    raw_link = f"https://discordapp.com/ra/{fingerprint}"
                    print(f"Grab Link: {raw_link}")
                    print("Saving QR...")
                    qr_image = qrcode.make(raw_link)
                    qr_image.save("qr.png")
                    print("Saved QR")
                    os.startfile("qr.png")
                elif response["op"] == "pending_login":
                    print("Login Detected")
                    encrypted_token = self.get_encrypted_token(response["ticket"])
                    decrypted_token = self.private_key.decrypt(base64.b64decode(bytes(encrypted_token, "utf8")), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode("utf8")
                    print(f"Token: {decrypted_token}")
                    self.closed = True
                    self.ws.close()
            except:
                pass

def main():
    client = RemoteAuthClient()
    client.main()
    print("Shutting Down...")
    sys.close()

if __name__ == "__main__":
    main()