import re
from typing import Final

import pyshark
from pwn import remote, log

PCAP_FILE = 'challenge.pcap'
SERVER_IP = '127.0.0.1'
SERVER_PORT = 20000

ACK: Final = b"*#*1##"
NACK: Final = b"*#*0##"

psw_regex = re.compile(r'\*#[0-9]{0,32}##')


def calculate_password(password: int, nonce: str) -> int:
    """
    Calculate password using the OpenWebNet algorithm.
    Source: https://www.rosettacode.org/wiki/OpenWebNet_password, https://github.com/karel1980/ReOpenWebNet/blob/master/src/reopenwebnet/password.py

    :param password: password
    :param nonce: nonce

    :return: hashed password
    """
    start = True
    num1 = 0
    num2 = 0

    for c in nonce:
        if c != "0":
            if start:
                num2 = password
            start = False
        if c == '1':
            num1 = (num2 & 0xFFFFFF80) >> 7
            num2 = num2 << 25
        elif c == '2':
            num1 = (num2 & 0xFFFFFFF0) >> 4
            num2 = num2 << 28
        elif c == '3':
            num1 = (num2 & 0xFFFFFFF8) >> 3
            num2 = num2 << 29
        elif c == '4':
            num1 = num2 << 1
            num2 = num2 >> 31
        elif c == '5':
            num1 = num2 << 5
            num2 = num2 >> 27
        elif c == '6':
            num1 = num2 << 12
            num2 = num2 >> 20
        elif c == '7':
            num1 = num2 & 0x0000FF00 | ((num2 & 0x000000FF) << 24) | ((num2 & 0x00FF0000) >> 16)
            num2 = (num2 & 0xFF000000) >> 8
        elif c == '8':
            num1 = (num2 & 0x0000FFFF) << 16 | (num2 >> 24)
            num2 = (num2 & 0x00FF0000) >> 8
        elif c == '9':
            num1 = ~num2
        else:
            num1 = num2

        num1 &= 0xFFFFFFFF
        num2 &= 0xFFFFFFFF
        if (c not in "09"):
            num1 |= num2

        num2 = num1
    return num1


def main():
    print("Starting solver...")
    cap = pyshark.FileCapture(PCAP_FILE, display_filter='tcp && !tls && tcp.port == 20000')

    # Extract encrypted password and nonce from pcap file
    # The nonce is sent from the server to the client
    # The password is sent from the client to the server
    nonce: str | None = None
    enc_password: str | None = None
    for packet in cap:
        try:
            tcp_data = packet.tcp.payload
        except AttributeError:
            continue
        else:
            tcp_data = tcp_data.replace(':', '')
            # Decode packet and remove ACK if present
            # Sometimes can happen that the ACK is appended to another message instead of being sent alone
            tcp_data = bytes.fromhex(tcp_data).decode('ascii', 'ignore').replace("*#*1##", "")
            if psw_regex.match(tcp_data):
                # 20000 is the port used by default by bticino devices
                # even if bticino has registered with IANA the port 20005 for this protocol
                # https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt

                # We need to get one of the pair (password, nonce) from the client and the other from the server
                if packet.tcp.dstport == '20000':
                    enc_password = tcp_data[2:-2]
                    log.info(f"Encrypted password: {enc_password}")
                elif packet.tcp.srcport == '20000':
                    nonce = tcp_data[2:-2]
                    log.info(f"Nonce: {nonce}")
                if enc_password is not None and nonce is not None:
                    break
    else:
        if enc_password is None or nonce is None:
            log.failure("Cannot find password or nonce in pcap file. Exiting...")
            return

    # Brute force the password
    log.info("Brute forcing the password...")
    # the minimum length of the nonce is always equal to length of the password
    max_password = int("9" * len(nonce))
    password: int | None = None
    # Try all numbers from 1 to max_password
    for i in range(1, max_password + 1):
        c_password = calculate_password(i, nonce)
        if str(c_password) == enc_password:
            password = i
            log.success(f"Password: {i}")
            break

    # Get the model name
    for packet in cap:
        if packet.tcp.srcport != '20000':
            continue
        try:
            tcp_data = packet.tcp.payload
        except AttributeError:
            continue
        else:
            tcp_data = tcp_data.replace(':', '')
            # Decode packet and remove ACK if present
            tcp_data = bytes.fromhex(tcp_data).decode('ascii', 'ignore').replace("*#*1##", "")
            if tcp_data.startswith('*#13**15') and tcp_data.endswith('##'):
                model_code = tcp_data[9:-2]

                # This is the list of all the known models from the documentation
                if model_code == '2':
                    model_name = 'MHServer'
                elif model_code == '4':
                    model_name = 'MH200'
                elif model_code == '6':
                    model_name = 'F452'
                elif model_code == '7':
                    model_name = 'F452V'
                elif model_code == '11':
                    model_name = 'MHServer2'
                elif model_code == '13':
                    model_name = 'H4684'
                else:
                    log.critical("Unknown device model")
                    return
                
                log.success(f"Model name: {model_name}")
                
                break

    # Get version
    for packet in cap:
        if packet.tcp.srcport != '20000':
            continue
        try:
            tcp_data = packet.tcp.payload
        except AttributeError:
            continue
        else:
            tcp_data = tcp_data.replace(':', '')
            # Decode packet and remove ACK if present
            tcp_data = bytes.fromhex(tcp_data).decode('ascii', 'ignore').replace("*#*1##", "")
            if tcp_data.startswith('*#13**16') and tcp_data.endswith('##'):
                values = tcp_data.split("*")
                v = values[4]
                r = values[5]
                b = values[6].replace("##", "")
                log.success(f"Version: {v}.{r}.{b}")
                break


    cap.close()
    log.success(f"Flag: snakeCTF{{{password}_{model_name}_{v}.{r}.{b}}}")


if __name__ == "__main__":
    main()
