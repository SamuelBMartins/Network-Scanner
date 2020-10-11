import socket
import sys


def my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def main():
    try:
        port = 443
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((my_ip(), port))
        s.listen()
        print('Server listening....')
    except PermissionError:
        print("Eseguirlo come root")
        sys.exit(1)

    while True:
        try:
            conn, addr = s.accept()
            print('Got connection from', addr)

            with open('remote_report.txt', 'wb') as f:
                data = conn.recv(1024)
                if not data:
                    continue
                f.write(data)

            print('Received file')
            conn.close()

        except KeyboardInterrupt:
            s.close()
            break


if __name__ == '__main__':
    main()
