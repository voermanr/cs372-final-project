import json
import select
import sys
import threading

import chatui
import socket as so

exit_command = ['/q', '/camp']
exit_flag = threading.Event()

PACKET_LENGTH_SIZE = 2


def monitor_input(name, socket):
    global exit_flag
    while True:
        prompt = f'{name}>'
        message = chatui.read_command(prompt)

        if message in exit_command:
            exit_flag.set()
            return

        message_packet = create_packet(name, 'chat', message)

        socket.sendall(message_packet)


def run_client(name: str, address, port):
    global exit_flag

    hello_packet = create_packet(name, packet_type="hello")

    chatui.init_windows()

    with so.socket() as socket:
        socket.connect((address, port))
        socket.sendall(hello_packet)

        sending_thread = threading.Thread(target=monitor_input, args=(name, socket))
        sending_thread.start()

        buffer = b''

        while not exit_flag.is_set():
            readable_sockets, _, _ = select.select({socket}, {}, {}, .001)
            for ready_socket in readable_sockets:
                data = ready_socket.recv(4096)

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
                            final_message = f"*** {packet_nick} has joined the chat."

                        elif packet_type == 'leave':
                            final_message = f"*** {packet_nick} has left the chat."

                        chatui.print_message(final_message)

        sending_thread.join()

        socket.close()

        chatui.end_windows()


def create_packet(name: str, packet_type: str, message: str = ''):
    payload = ''

    if packet_type == 'hello':
        payload = json.dumps({"type": "hello", "nick": name}).encode("UTF-8")

    elif packet_type == 'chat':
        payload = json.dumps({"type": "chat", "message": message}).encode("UTF-8")

    pay_len = len(payload)

    payload_length = pay_len.to_bytes(PACKET_LENGTH_SIZE, 'big', signed=False)

    packet = payload_length + payload

    return packet


def usage():
    print("usage: chat_client.py name address port", file=sys.stderr)


def main(argv):
    try:
        name = argv[1]
        address = argv[2]
        port = int(argv[3])
    except:
        usage()
        return 1

    run_client(name, address, port)


if __name__ == '__main__':
    sys.exit(main(sys.argv))