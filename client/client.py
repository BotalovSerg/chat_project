import os
import sys
import rsa
import time
import shelve
import socket
import threading
from PyQt5 import QtCore, QtGui, QtWidgets
from des import *

# Мониторинг входящих сообщений
class MessageMonitor(QtCore.QThread):
    mysignal = QtCore.pyqtSignal(str)

    def __init__(self, server_socket, private_key, parent=None):
        QtCore.QThread.__init__(self, parent)
        self.server_socket = server_socket
        self.private_key = private_key
        self.message = None

    def run(self):
        while True:
            try:
                self.message = self.server_socket.recv(1024)
                decrypt_message = rsa.decrypt(self.message, self.private_key)
                self.mysignal.emit(decrypt_message.decode('utf-8'))
            except:
                self.mysignal.emit(self.message.decode('utf-8'))


class Client(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ip = None
        self.port = None
        self.friend_public_key = None

        self.mypublickey = None
        self.myprivatekey = None

        if len(os.listdir('friend_id')) == 0:
            self.ui.lineEdit.setEnabled(False)
            self.ui.pushButton.setEnabled(False)
            self.ui.pushButton_2.setEnabled(False)
            self.ui.pushButton_4.setEnabled(False)
            message = "Поместите идентификатор собеседника в 'friend_id'"
            self.ui.plainTextEdit.appendPlainText(message)

        if not os.path.exists('private'):
            self.ui.lineEdit.setEnabled(False)
            self.ui.pushButton.setEnabled(False)
            self.ui.pushButton_2.setEnabled(False)
            self.ui.pushButton_4.setEnabled(False)
            message = "Также необходимо сгенировровать свой идентификатор"
            self.ui.plainTextEdit.appendPlainText(message)

        else:
            with shelve.open('private') as file:
                self.mypublickey = file['pubkey']
                self.myprivatekey = file['privkey']
                self.ip = file['ip']
                self.port = file['port']

            with shelve.open(os.path.join('friend_id', os.listdir('friend_id')[0])) as file:
                self.friend_public_key = file['pubkey']

            message = "Connect to the server"
            self.ui.plainTextEdit.appendPlainText(message)
            self.ui.lineEdit.setEnabled(False)
            self.ui.pushButton.setEnabled(False)
            self.ui.pushButton_2.setEnabled(True)
            self.ui.pushButton_4.setEnabled(False)

        self.ui.pushButton_2.clicked.connect(self.connect_server)
        self.ui.pushButton.clicked.connect(self.send_message)
        self.ui.pushButton_5.clicked.connect(self.generate_encrypt)
        self.ui.pushButton_4.clicked.connect(self.clear_panel)
    
    def connect_server(self):
        try:
            self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_client.connect((self.ip, self.port)); time.sleep(2)

            # Запуск мониторинга входящих сообщений
            self.message_monitor = MessageMonitor(self.tcp_client, self.myprivatekey)
            self.message_monitor.mysignal.connect(self.update_chat)
            self.message_monitor.start()

            self.ui.lineEdit_4.setEnabled(False)
            self.ui.lineEdit_5.setEnabled(False)
            self.ui.pushButton_2.setEnabled(False)
            self.ui.pushButton.setEnabled(True)
            self.ui.lineEdit.setEnabled(True)
            self.ui.pushButton_4.setEnabled(True)
            self.ui.pushButton_5.setEnabled(False)
        except:
            self.ui.plainTextEdit.clear()
            self.ui.plainTextEdit.appendPlainText('Error connect of server')
            self.ui.plainTextEdit.appendPlainText('Fix id and try again')

    def send_message(self):
        try:
            if len(self.ui.lineEdit.text()) > 0:
                message = self.ui.lineEdit.text()
                crypto_massage = rsa.encrypt(message.encode('utf-8'), self.friend_public_key)

                self.ui.plainTextEdit.appendPlainText(f'[You]: {message}')
                self.tcp_client.send(crypto_massage)
                self.ui.lineEdit.clear()
        except:
            sys.exit()

    def generate_encrypt(self):
        if len(self.ui.lineEdit_4.text()) > 0:
            if len(self.ui.lineEdit_5.text()) > 0:
                (pubkey, privkey) = rsa.newkeys(512)

                with shelve.open('your_id') as file:
                    file['pubkey'] = pubkey
                    file['id'] = str(self.ui.lineEdit_4.text())
                    file['port'] = int(self.ui.lineEdit_5.text())

                with shelve.open('private') as file:
                    file['pubkey'] = pubkey
                    file['privkey'] = privkey
                    file['id'] = str(self.ui.lineEdit_4.text())
                    file['port'] = int(self.ui.lineEdit_5.text())

                self.ui.plainTextEdit_2.appendPlainText('Создаем "your_id" идентификатор')
                self.ui.plainTextEdit_2.appendPlainText('Передайте его собеседнику и начните диалог')
            else:
                self.ui.plainTextEdit_2.clear()
                self.ui.plainTextEdit_2.appendPlainText('Проверьте правильность вводимых данных')
        else:
            self.ui.plainTextEdit_2.clear()
            self.ui.plainTextEdit_2.appendPlainText('Проверьте правильность вводимых данных')

    def closeEvent(self, event):
        try:
            self.tcp_client.send(b'exit')
            self.tcp_client.close()
        except:
            pass

    
    def update_chat(self, value):
        self.ui.plainTextEdit.appendHtml(value)

    
    def clear_panel(self):
        self.ui.plainTextEdit.clear()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    myapp = Client()
    myapp.show()
    sys.exit(app.exec_())

