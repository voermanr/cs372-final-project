import json
import sys
import threading

import chatui
import socket as so

exit_command = ['/q', '/camp']

PACKET_LENGTH_SIZE = 2


def monitor_input(name, socket):
    while True:
        prompt = f'{name}>'
        message = chatui.read_command(prompt)

        if message in exit_command:
            return

        message_packet = create_packet(name, 'chat', message)

        socket.sendall(message_packet)

        # chatui.print_message(message)


def receive_and_display(socket):
    while socket:
        buffer = b''
        data = socket.recv(4096)

        if len(data) != 0:
            buffer += data

        buffer_len = len(buffer)

        if buffer_len >= PACKET_LENGTH_SIZE:
            packet_size = PACKET_LENGTH_SIZE + int.from_bytes(buffer[:PACKET_LENGTH_SIZE], "big")

            if buffer_len >= packet_size:
                packet = buffer[:packet_size]
                buffer = buffer[packet_size:]

                trimmed_packet = packet[PACKET_LENGTH_SIZE:]
                json_packet = json.loads(trimmed_packet)

                packet_type = json_packet['type']
                packet_nick = json_packet.get('nick', '')
                packet_message = json_packet.get('message', '')

                final_message = ''

                if packet_type == 'chat':
                    final_message = f"{packet_nick}: {packet_message}"

                elif packet_type == 'join':
                    final_message = f"*** {packet_nick} has joined the cat. meow"

                chatui.print_message(final_message)


def run_client(name: str):

    hello_packet = create_packet(name, packet_type="hello")

    chatui.init_windows()

    socket = so.socket()
    socket.connect(('localhost', 3490))
    socket.sendall(hello_packet)

    sending_thread = threading.Thread(target=monitor_input, args=(name, socket))
    sending_thread.start()

    receving_thread = threading.Thread(target=receive_and_display, args=(socket, ))
    receving_thread.start()

    sending_thread.join()
    receving_thread.join()

    socket.close()

    chatui.end_windows()


def create_packet(name: str, packet_type: str, message: str = ''):
    payload = ''

    if packet_type == 'hello':
        payload = json.dumps({"type": "hello", "nick": name}).encode("UTF-8")

    elif packet_type == 'chat':
        payload = json.dumps({"type": "chat", "message": message}).encode("UTF-8")

    #print(f"payload:\n\t{payload}")

    pay_len = len(payload)
    #print(f"pay_len:\n\t{pay_len}")

    payload_length = pay_len.to_bytes(PACKET_LENGTH_SIZE, 'big', signed=False)
    #print(f"payload_length:\n\t{payload_length}")

    packet = payload_length + payload
    #print(f"packet:\n\t{packet}")

    return packet




def usage():
    print("usage: chat_client.py name", file=sys.stderr)


def main(argv):
    try:
        name = argv[1]
    except:
        usage()
        return 1

    run_client(name)


if __name__ == '__main__':
    sys.exit(main(sys.argv))