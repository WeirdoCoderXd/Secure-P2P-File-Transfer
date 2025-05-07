Secure P2P File Transfer
simple script to send files between two computers over the internet using encryption

uses x25519 for key exchange and aes-gcm for encrypting the actual data
basically secure peer to peer file transfer with no servers or cloud



install pip install cryptography 

usage
run server (receives file)
python secure_p2p_file_transfer.py --mode server --host 0.0.0.0 --port 5000 --output-dir received_files

you can change the host and port if needed
received files go to received_files folder (or whatever you set)

run client (sends file)

python secure_p2p_file_transfer.py --mode client --host <server_ip> --port 5000 --file path/to/your/file

just point to the right IP and file path
how it works
both sides generate x25519 keys and exchange them
shared secret is derived and used as AES key
data is encrypted using aes-gcm with a fresh nonce for every chunk
the file is sent in pieces, each encrypted
things to know
no compression or chunk merging, just raw encrypted chunks
you need to run the server first
no GUI or progress bar, just simple prints
works best on LAN or over port-forwarded connections

example
on server
python secure_p2p_file_transfer.py --mode server --host 0.0.0.0 --port 5000

on client 
python secure_p2p_file_transfer.py --mode client --host 192.168.0.10 --port 5000 --file myfile.txt

DONE

this is only theory idk tbh
