import select
import socket as so
import json
import sys

PACKET_LENGTH_SIZE = 2


def create_packet(name: str, packet_type: str, message: str = ''):
    payload = ''
    if packet_type == 'chat':
        payload = json.dumps({"type": packet_type, "nick": name, "message": message}).encode("UTF-8")

    elif packet_type == 'join':
        payload = json.dumps({"type": packet_type, "nick": name}).encode("UTF-8")

    elif packet_type == 'leave':
        payload = json.dumps({"type": packet_type, "nick": name}).encode("UTF-8")

    pay_len = len(payload)

    payload_length = pay_len.to_bytes(PACKET_LENGTH_SIZE, 'big', signed=False)

    packet = payload_length + payload

    return packet


def run_server(port: int):
    listening_socket = build_listening_socket(port)

    reading_sockets = {listening_socket}
    packet_buffers = { }
    clients = { }

    while True:
        ready_socket, _, _ = select.select(reading_sockets, {}, {})

        for socket in ready_socket:
            if socket is listening_socket:
                handle_new_connection(packet_buffers, reading_sockets, socket)

            else:
                buffer = packet_buffers[socket]

                data = socket.recv(4096)

                if len(data) != 0:
                    buffer += data
                    packet_buffers[socket] = buffer

                else:
                    handle_client_leaving(clients, reading_sockets, socket)

        for socket, potential_packet in packet_buffers.items():

            packet_buffer_len = len(potential_packet)

            if packet_buffer_len >= PACKET_LENGTH_SIZE:
                packet_size = PACKET_LENGTH_SIZE + int.from_bytes(potential_packet[:PACKET_LENGTH_SIZE], "big")

                if packet_buffer_len >= packet_size:
                    packet_message, packet_nick, packet_type = split_package(packet_buffers, packet_size,
                                                                             potential_packet, socket)

                    if packet_type == 'hello':
                        handle_hello_packet(clients, packet_nick, socket)

                    elif packet_type == 'chat':
                        handle_chat_packet(clients, packet_message, packet_type, socket)


def handle_chat_packet(clients, packet_message, packet_type, socket):
    broadcast_list = clients.copy()
    broadcaster = broadcast_list.pop(socket)
    for dest_socket in clients.keys():
        message_packet = create_packet(broadcaster, packet_type, packet_message)
        dest_socket.sendall(message_packet)


def handle_hello_packet(clients, packet_nick, socket):
    clients[socket] = packet_nick
    broadcast_list = clients.copy()
    broadcast_list.pop(socket)
    for dest_socket in broadcast_list.keys():
        join_packet = create_packet(packet_nick, 'join')
        dest_socket.sendall(join_packet)


def split_package(packet_buffers, packet_size, potential_packet, socket):
    packet = potential_packet[:packet_size]
    packet_buffers[socket] = potential_packet[packet_size:]
    trimmed_packet = packet[PACKET_LENGTH_SIZE:]
    json_packet = json.loads(trimmed_packet)
    packet_type = json_packet['type']
    packet_nick = json_packet.get('nick', '')
    packet_message = json_packet.get('message', '')
    return packet_message, packet_nick, packet_type


def handle_client_leaving(clients, reading_sockets, socket):
    reading_sockets.remove(socket)
    leaving_client = clients.pop(socket)
    socket.close()
    for dest_socket in clients.keys():
        leave_packet = create_packet(leaving_client, 'leave')
        dest_socket.sendall(leave_packet)


def handle_new_connection(packet_buffers, reading_sockets, socket):
    new_socket, _ = socket.accept()
    reading_sockets.add(new_socket)
    packet_buffers[new_socket] = b''


def build_listening_socket(port):
    listening_socket = so.socket()
    listening_socket.setsockopt(so.SOL_SOCKET, so.SO_REUSEADDR, 1)
    listening_socket.bind(('', port))
    listening_socket.listen()
    return listening_socket


def usage():
    print("usage: chat_server.py port", file=sys.stderr)


def main(argv):
    try:
        port = int(argv[1])
    except:
        usage()
        return 1

    run_server(port)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
