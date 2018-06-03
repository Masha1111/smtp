import socket
import argparse
import ssl
import sys
import os
import re
import base64


def parse(dir):
    with open(dir + '\config.txt') as f:
        data = f.readlines()
        if len(data) < 1:
            sys.exit("Напишите конфигурацию")
        emails = []
        for address in re.findall('([\w.]+?@(\w+)\.ru)', data[0]):
            if address[1] != 'mail' and address[1] != 'yandex' and address[1] != 'rambler':
                sys.exit("неопознанный домен")

            else:
                emails.append(address[0])
        if not emails:
            sys.exit("укажите адреса")
        try:
            if len(data) > 1:
                theme = re.search('Theme: (.*)\n', data[1]).group(1)
        except AttributeError:
            theme = ''
        files = {}
        file_flag = False
        try:
            if len(data) == 3:
                file_flag = True
                res = str(re.search('Files: (.*)', data[2]).group(1))
                files = {file for file in re.findall(r'([_\w+]*\.\w+)', res)}
        except AttributeError:
            pass
    return emails, theme, files, file_flag


def main(emails, theme, files, text, login, password, dir):
    for email in emails:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock = ssl.wrap_socket(sock)
            name_server = re.search('@(.*)\.ru', email).group(1)
            sock.connect(('smtp.' + name_server + '.ru', 465))
            try:
                data = sock.recv(1024).decode()
                if data[0] != "2":
                    sys.exit("Проблемы соединения\n" + data)
                try:
                    sock.send(b"EHLO Sender\n")
                    data = sock.recv(4096).decode()
                    if data[0] != "2":
                        sys.exit("Проблемы EHLO\n" + data)
                except socket.timeout:
                    sys.exit("Таймаут EHLO")
                auth(sock, login, password)
            except:
                sys.exit("Таймаут")
            try:
                sock.send(("MAIL FROM: " + login + "\n").encode())
                data = sock.recv(4096).decode()
                if data[0] != "2":
                    sys.exit("Проблемы MAIL\n" + data)
            except socket.timeout:
                sys.exit("Таймаут MAIL")
            try:
                sock.send(("RCPT TO: " + email + "\n").encode())
                data = sock.recv(4096).decode()
                if data[0] != "2":
                    sys.exit("Проблемы RCPT\n" + data)
            except socket.timeout:
                sys.exit("Таймаут RCPT")
            send_data(sock, login, email, theme, text, files, dir)
            try:
                sock.send("QUIT\r\n".encode())
                data = sock.recv(4096).decode()
                if data[0] != "2":
                    sys.exit("Проблемы с QUIT\n" + data)
                print("Письмо отправлено")
            except socket.timeout:
                sys.exit("Таймаут QUIT")


def send_data(sock, login, email, theme, text, files, directory):
    try:
        sock.send("DATA\n".encode())
        data = sock.recv(4096).decode()
        if data[0] != "3":
            sys.exit("Проблемы DATA\n" + data)
        msg = []
        msg.append("From: {0}\n".format(login))
        msg.append("To: {0}\n".format(email))
        msg.append("Subject: {0}\n".format(theme))
        msg.append('Content-Type: multipart/mixed; boundary="C6y6NN0QaSkb14zK9VQuBtUq0M8SufNy"\n\n')
        msg.append("--C6y6NN0QaSkb14zK9VQuBtUq0M8SufNy\n")
        msg.append("Content-Type: text/plain\n\n")
        msg.append(text + "\n")
        re_files = re.compile('(jpeg|jpg|png|txt|pdf)')
        dict_images = dict()
        content_type = {'jpeg': "image/jpeg", 'jpg': "image/jpg", 'png': "image/png",
                        'txt': "text/plain", 'pdf': "application/pdf"}
        for file in files:
            t = re_files.findall(file)
            if t:
                with open(directory + "/files/" + file, "rb") as b_file:
                    try:
                        encoded_string = base64.encodestring(b_file.read())
                        dict_images[file] = (content_type[t[0]], encoded_string.decode())
                    except Exception:
                        print('\nПроблема с файлом ' + str(file) + '\n')
                        continue
        for file in dict_images.keys():
            msg.append("--C6y6NN0QaSkb14zK9VQuBtUq0M8SufNy\n")
            msg.append('Content-Disposition: attachment; filename="{0}"\n'.format(file))
            msg.append("Content-Transfer-Encoding: base64\n")
            msg.append('Content-Type: {0}; name="{1}"\n\n'.format(dict_images[file][0], file))
            msg.append(dict_images[file][1])
            msg.append("\n\n")
        msg.append("--C6y6NN0QaSkb14zK9VQuBtUq0M8SufNy\n.\n")
        sock.send("".join(msg).encode())
        data = sock.recv(4096).decode()
        if data[0] != "2":
            sys.exit("Проблемы с отправкой\n" + data)
    except socket.timeout:
        sys.exit("Таймаут DATA")


def auth(sock, log, pas):
    try:
        sock.send(b"AUTH LOGIN\n")
        data = sock.recv(4096).decode()
        if data[0] != "3":
            sys.exit("Проблемы с AUTH\n" + data)
        sock.send((base64.b64encode(log.encode()).decode() + "\n").encode())
        data = sock.recv(4096).decode()
        if data[0] != "3":
            sys.exit("Проблемы с AUTH\n" + data)
        sock.send((base64.b64encode(pas.encode()).decode() + "\n").encode())
        data = sock.recv(4096).decode()
        if data[0] != "2":
            sys.exit("Проблемы с AUTH\n" + data)
    except socket.timeout:
        sys.exit("Таймаут AUTH")


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", type=str, help="логин")
    parser.add_argument("-p", type=str, help="пароль")
    return parser.parse_args()


def get_count_points(matchobj):
    points = '.' * (len(matchobj.group(1)) + 1)
    return points


if __name__ == '__main__':
    args = get_args()
    if not os.path.exists("C:\\Users\\lorti\\Documents\\МатМех\\протоколы\\smtp" + '\config.txt'):
        sys.exit("Проверьте параметры")
    emails, theme, files, flag = parse("C:\\Users\\lorti\\Documents\\МатМех\\протоколы\\smtp")
    if not files and flag:
        sys.exit("Поместите файлы в папку")
    with open("C:\\Users\\lorti\\Documents\\МатМех\\протоколы\\smtp" + r'\mail.txt', 'r') as f:
        text_file = f.read()


        reg = re.compile('$(\w+|$\#])\.+')
        points_pattern = re.compile('(\.+)')
        strings = text_file.split('\n')
        res = ''
        for line in strings:
            line = re.sub(points_pattern, get_count_points, line)
            if reg.search(line) is not None:
                res += line[0:len(line) - 1] + '\n'
            else:
                res += line + '\n'
        res = res[0:len(res) - 1]


    main(emails, theme, files, res, args.l, args.p, "C:\\Users\\lorti\\Documents\\МатМех\\протоколы\\smtp")
