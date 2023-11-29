import sys

import chatui


def run_client():
    chatui.init_windows()

    while True:
        s = chatui.read_command('gimme something>')
        chatui.print_message(s)


def usage():
    print("usage: chat_client.py name", file=sys.stderr)


def main(argv):
    try:
        name = argv[1]
    except:
        usage()
        return 1

    run_client()

if __name__ == '__main__':
    sys.exit(main(sys.argv))