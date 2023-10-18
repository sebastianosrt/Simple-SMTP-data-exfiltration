#!/bin/python3
import asyncio
from aiosmtpd.controller import Controller
from email import message_from_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import os
import json
import re
import math

DATA_DIR = "./data"
CHUNKS_DIR = "./data/chunks"
HOSTNAME = "0.0.0.0"
PORT = "25"


def decrypt_aes(encrypted_string, key="MySecretKeysssss"):
    encrypted_bytes = base64.b64decode(encrypted_string)
    cipher = AES.new(key.encode(), AES.MODE_CBC, key.encode())
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    return unpad(decrypted_bytes, AES.block_size).decode()


def reassemble_file(file_name):
    chunk_files = [file for file in os.listdir(CHUNKS_DIR) if file.endswith(file_name)]
    # sort chunks
    chunk_files.sort(key=lambda x: int(re.findall(r"\d+", x)[0]))
    # create reassembled file
    reassembled_file_path = os.path.join(DATA_DIR, file_name)
    reassembled_file = open(reassembled_file_path, "wb")
    try:
        for chunk_file in chunk_files:  # iterate through chunk files
            chunk_file_path = os.path.join(CHUNKS_DIR, chunk_file)
            with open(chunk_file_path, "rb") as chunk:  # read chunk
                chunk_data = chunk.read()
            reassembled_file.write(chunk_data)  # write chunk into reassebled file
            os.remove(chunk_file_path)  # delete the chunk file
        print("[+] Reassembled file saved as:", file_name)

    finally:
        reassembled_file.close()


def write_file(output_dir, file_name, data):
    fil = open(os.path.join(output_dir, file_name), "wb")
    try:
        fil.write(base64.b64decode(data))
    except:
        print("[-] Failed to write data")
    finally:
        fil.close()


class SMTPServerHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        email_message = message_from_bytes(envelope.content)
        try:
            body = email_message.get_payload(decode=True).decode()  # get email body
            decrypted = decrypt_aes(body)  # decrypt body
            content = json.loads(decrypted)  # load body as json

            file_path, file_size, chunk_size, chunkn, data = (
                content["fileName"],
                content["fileSize"],
                content["chunkSize"],
                content["chunkn"],
                content["data"],
            )
            chunks = file_size / chunk_size
            file_name = re.findall(
                r'[^\\\/:*?"<>|\r\n]+$', file_path.replace("\\", "/")
            )[
                0
            ]  # get filename from path

            if chunks <= 1:  # save directly
                write_file(DATA_DIR, file_name, data)
                print("[+] File saved as:", file_name)
            else:  # save chunks and reassemble
                write_file(CHUNKS_DIR, f"chunk-{str(chunkn)}-{file_name}", data)
                if math.ceil(file_size / (chunk_size * chunkn)) <= 1:  # last chunk
                    reassemble_file(file_name)
        except Exception as e:
            print(f"[-] Something went wrong: {str(e)}")
        return "250 Message accepted for delivery"


async def main():
    handler = SMTPServerHandler()
    controller = Controller(handler, hostname=HOSTNAME, port=PORT)
    controller.start()
    print("[+] SMTP server started...")
    # create output folders if not exsists
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    if not os.path.exists(CHUNKS_DIR):
        os.makedirs(CHUNKS_DIR)
    # run
    try:
        while True:
            await asyncio.sleep(2)
    except:
        controller.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except:
        print("[+] SMTP server stopped")
