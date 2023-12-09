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

    # print(f"payload:\n\t{payload}")

    pay_len = len(payload)
    # print(f"pay_len:\n\t{pay_len}")

    payload_length = pay_len.to_bytes(PACKET_LENGTH_SIZE, 'big', signed=False)
    # print(f"payload_length:\n\t{payload_length}")

    packet = payload_length + payload
    # print(f"packet:\n\t{packet}")

    return packet


def run_server(port: int):
    listening_socket = so.socket()
    listening_socket.setsockopt(so.SOL_SOCKET, so.SO_REUSEADDR, 1)
    listening_socket.bind(('', port))
    listening_socket.listen()

    reading_sockets = {listening_socket}

    packet_buffers = {}
    clients = {}

    while True:
        ready_socket, _, _ = select.select(reading_sockets, {}, {})

        for socket in ready_socket:
            if socket is listening_socket:
                new_socket, _ = socket.accept()
                # print(f"Accepted connection from {new_socket}")
                reading_sockets.add(new_socket)

                packet_buffers[new_socket] = b''
                # print(f"Setting up buffer for {new_socket}")

            else:
                # print(f"Someone is sending me something")
                buffer = packet_buffers[socket]

                data = socket.recv(4096)

                # print(f"Got {data}")

                if len(data) != 0:
                    buffer += data
                    # print(f"Stuffed buffer with data, buffer:\t{buffer}")
                    packet_buffers[socket] = buffer

                else:
                    # print(f"Someone is done with us")
                    reading_sockets.remove(socket)
                    leaving_client = clients.pop(socket)
                    socket.close()

                    for dest_socket in clients.keys():
                        leave_packet = create_packet(leaving_client, 'leave')
                        dest_socket.sendall(leave_packet)

        for socket, potential_packet in packet_buffers.items():
            # print(f"socket: {socket}\npotential_packet: {potential_packet}")
            packet_buffer_len = len(potential_packet)
            # print(f"packet_buffer_len: {packet_buffer_len}")

            if packet_buffer_len >= PACKET_LENGTH_SIZE:
                packet_size = PACKET_LENGTH_SIZE + int.from_bytes(potential_packet[:PACKET_LENGTH_SIZE], "big")
                # print(f"packet_size: {packet_size}")
                if packet_buffer_len >= packet_size:
                    packet = potential_packet[:packet_size]
                    packet_buffers[socket] = potential_packet[packet_size:]

                    # print(f"Found a packet:\t{packet}")

                    trimmed_packet = packet[PACKET_LENGTH_SIZE:]
                    # print(f"trimmed_packet: {trimmed_packet}")
                    json_packet = json.loads(trimmed_packet)
                    # print(json_packet)

                    packet_type = json_packet['type']
                    packet_nick = json_packet.get('nick', '')
                    packet_message = json_packet.get('message', '')

                    if packet_type == 'hello':
                        # print(f"Found a new client, adding {packet_nick} to the client list")
                        clients[socket] = packet_nick

                        broadcast_list = clients.copy()
                        broadcast_list.pop(socket)

                        for dest_socket in broadcast_list.keys():
                            join_packet = create_packet(packet_nick, 'join')
                            dest_socket.sendall(join_packet)

                    elif packet_type == 'chat':
                        broadcast_list = clients.copy()
                        broadcaster = broadcast_list.pop(socket)

                        # print(f"{clients[socket]} sent a message, rebroadcasting it to {clients.values()}")
                        for dest_socket in clients.keys():
                            message_packet = create_packet(broadcaster, packet_type, packet_message)
                            dest_socket.sendall(message_packet)


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
