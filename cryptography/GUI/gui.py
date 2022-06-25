# -*- coding: utf-8 -*-

from ..DES import cryptography_des
from ..DES import file_encryptor
from ..MD5 import cryptography_md5
from ..RSA import cryptography_rsa
from ..AES import aes
from PyQt5.QtWidgets import QWidget, QLabel, QPushButton, QComboBox, QApplication, QTextEdit, QFileDialog, QMainWindow, QApplication, QVBoxLayout, QTabWidget, QHBoxLayout, QSpacerItem, QMessageBox, QGridLayout, QFrame, QSizePolicy 
from PyQt5.QtCore import pyqtSlot, Qt
from PyQt5.QtGui import QIcon, QFont, QPixmap

import sys
import os
import os.path
import time
sys.path.append(os.path.abspath('../AES'))

INITIAL_WIDTH  = 800
INITIAL_HEIGHT = 600
TEXT_HEIGHT    = 40
FONT = "Consolas"

# MARGINS
LEFT = 20
TOP = 20
RIGHT = 20
BOTTOM = 20

class App(QMainWindow):
    def __init__(self):
        super().__init__()

        self.title  = 'Applications of Cryptography'
        self.left   = 550
        self.top    = 200
        self.width  = INITIAL_WIDTH
        self.height = INITIAL_HEIGHT
        self.setWindowTitle(self.title)
        self.setGeometry(self.left ,self.top, self.width, self.height)       
        self.table_widget = MyTableWidget(self)
        self.setCentralWidget(self.table_widget)
        self.show()
        

class MyTableWidget(QWidget):        
 
    def __init__(self, parent):   
        super(QWidget, self).__init__(parent)

        self.filePath = "" # file path for whatever file
        self.layout = QVBoxLayout(self)
        

        # Initialize tab screen
        self.tabs = QTabWidget()
        self.tabAES = QWidget()	
        self.tabDES = QWidget()
        self.tabMD5 = QWidget()
        self.tabRSA = QWidget()
        self.tabSHA = QWidget()
        self.tabVIG = QWidget()
            
        self.tabs.resize(INITIAL_WIDTH,INITIAL_HEIGHT) 
 
        # Add tabs
        self.tabs.addTab(self.tabAES,"AES")
        self.tabs.addTab(self.tabDES,"DES")
        self.tabs.addTab(self.tabMD5,"MD5")
        self.tabs.addTab(self.tabRSA,"RSA")
 
        # Create AES tab
        self.labelAESKey      = QLabel("Key:",self)
        self.labelAESPlain    = QLabel("Plain Text:",self)
        self.labelAESCypher   = QLabel("Cipher Text:",self)
        self.buttonAESEncrypt = QPushButton("Encrypt\n>>>",self)
        self.buttonAESDecrypt = QPushButton("Decrypt\n<<<",self)
        self.textAESPlain     = QTextEdit(self)
        self.textAESCypher    = QTextEdit(self)
        self.textAESKey       = QTextEdit(self)
        self.comboAESMode     = QComboBox(self)
        
        self.comboAESMode.addItem("OFB")
        self.comboAESMode.addItem("CFB")
        self.comboAESMode.addItem("CBC")
        
        self.layoutAESButton = QVBoxLayout()
        self.layoutAESButton.setContentsMargins(LEFT, 0, RIGHT, 0)
        self.layoutAESButton.setSpacing(50)

        self.layoutAESButton.addStretch() 
        self.layoutAESButton.addWidget(self.buttonAESEncrypt)
        self.layoutAESButton.addWidget(self.buttonAESDecrypt)
        self.layoutAESButton.addStretch()

        self.layoutAESLeft = QVBoxLayout()
        self.layoutAESLeft.setSpacing(10)
        self.layoutAESLeft.addWidget(self.labelAESPlain)
        self.layoutAESLeft.addWidget(self.textAESPlain)
        self.layoutAESLeft.setContentsMargins(LEFT, 0 , RIGHT, BOTTOM) 
        
        self.layoutAESRight = QVBoxLayout()
        self.layoutAESLeft.setSpacing(10)
        self.layoutAESRight.addWidget(self.labelAESCypher)
        self.layoutAESRight.addWidget(self.textAESCypher)
        self.layoutAESRight.setContentsMargins(LEFT, 0, BOTTOM, RIGHT)
        
        self.layoutAESText = QHBoxLayout()
        self.layoutAESText.addLayout(self.layoutAESLeft)
        self.layoutAESText.addLayout(self.layoutAESButton)
        self.layoutAESText.addLayout(self.layoutAESRight)
        
        self.layoutAESKey = QHBoxLayout()
        self.layoutAESKey.setSpacing(20)
        self.layoutAESKey.setContentsMargins(LEFT, TOP, BOTTOM, RIGHT)
        self.layoutAESKey.addWidget(self.labelAESKey)
        self.layoutAESKey.addWidget(self.textAESKey)
        self.layoutAESKey.addWidget(self.comboAESMode)
        
        self.layoutAES = QVBoxLayout()
        self.layoutAES.addLayout(self.layoutAESKey)
        self.layoutAES.addLayout(self.layoutAESText)
        
        self.tabAES.setLayout(self.layoutAES)
        self.textAESKey.setFixedHeight(TEXT_HEIGHT) 
        
        self.buttonAESEncrypt.clicked.connect(self._AESEncrypt)
        self.buttonAESDecrypt.clicked.connect(self._AESDecrypt)
        
        # Create DES tab
        
        self.labelDESKey          = QLabel("Key:",self)
        self.labelDESPlain        = QLabel("Plain Text:",self)
        self.labelDESCypher       = QLabel("Cipher Text:",self)
        self.labelDESInitVec      = QLabel("Initial vector:",self)
        self.labelDESPlainFile    = QLabel("",self)
        self.labelDESCypherFile   = QLabel("",self) 
        self.buttonDESEncrypt     = QPushButton("Encrypt",self)
        self.buttonDESDecrypt     = QPushButton("Decrypt",self)
        self.buttonDESEncryptFile = QPushButton("Encrypt file:",self)
        self.buttonDESDecryptFile = QPushButton("Decrypt file:",self)
        self.textDESPlain         = QTextEdit(self)
        self.textDESCypher        = QTextEdit(self)
        self.textDESKey           = QTextEdit(self)
        self.textDESInitVec       = QTextEdit(self)
        self.comboDESMode         = QComboBox(self)
        
        self.comboDESMode.addItem("ECB")
        self.comboDESMode.addItem("CBC")
        self.comboDESMode.addItem("3-DES")
        
        self.layoutDESButton = QVBoxLayout()
        self.layoutDESButton.addStretch()
        self.layoutDESButton.addWidget(self.buttonDESEncrypt)
        self.layoutDESButton.addStretch()
        self.layoutDESButton.addWidget(self.buttonDESDecrypt)
        self.layoutDESButton.addStretch()
        
        self.layoutDESLeftButtom = QHBoxLayout()
        self.layoutDESLeftButtom.addWidget(self.buttonDESEncryptFile)
        self.layoutDESLeftButtom.addWidget(self.labelDESPlainFile)

        self.layoutDESLeft = QVBoxLayout()
        self.layoutDESLeft.addWidget(self.labelDESPlain)
        self.layoutDESLeft.addWidget(self.textDESPlain)
        self.layoutDESLeft.addLayout(self.layoutDESLeftButtom)
        
        self.layoutDESRightButtom = QHBoxLayout()
        self.layoutDESRightButtom.addWidget(self.buttonDESDecryptFile)
        self.layoutDESRightButtom.addWidget(self.labelDESCypherFile)

        self.layoutDESRight = QVBoxLayout()
        self.layoutDESRight.addWidget(self.labelDESCypher)
        self.layoutDESRight.addWidget(self.textDESCypher)
        self.layoutDESRight.addLayout(self.layoutDESRightButtom)
        
        self.layoutDESText = QHBoxLayout()
        self.layoutDESText.addLayout(self.layoutDESLeft)
        self.layoutDESText.addLayout(self.layoutDESButton)
        self.layoutDESText.addLayout(self.layoutDESRight)
        
        self.layoutDESKeyKey = QHBoxLayout()
        self.layoutDESKeyKey.addWidget(self.comboDESMode)
        self.layoutDESKeyKey.addWidget(self.labelDESKey)
        self.layoutDESKeyKey.addWidget(self.textDESKey)
        
        self.layoutDESInitVec = QHBoxLayout()
        self.layoutDESInitVec.addWidget(self.labelDESInitVec)
        self.layoutDESInitVec.addWidget(self.textDESInitVec)
        
        self.layoutDESKey = QVBoxLayout()
        self.layoutDESKey.setContentsMargins(LEFT, TOP, RIGHT, BOTTOM)
        self.layoutDESKey.addLayout(self.layoutDESInitVec)
        self.layoutDESKey.addLayout(self.layoutDESKeyKey)
        
        self.layoutDES = QVBoxLayout()
        self.layoutDES.addLayout(self.layoutDESKey)
        self.layoutDES.addLayout(self.layoutDESText)
        
        self.tabDES.setLayout(self.layoutDES)
        self.textDESKey.setFixedHeight(TEXT_HEIGHT) 
        self.textDESInitVec.setFixedHeight(TEXT_HEIGHT)
        
        self.buttonDESEncrypt.clicked.connect(self._DESEncrypt)
        self.buttonDESDecrypt.clicked.connect(self._DESDecrypt)
        self.buttonDESEncryptFile.clicked.connect(self._DESEncryptFile)
        self.buttonDESDecryptFile.clicked.connect(self._DESDecryptFile)
        
        # Create MD5 tab
        
        self.labelMD5Plain    = QLabel("Plain Text:",self)
        self.labelMD5Digest   = QLabel("Digest Text:",self)
        self.labelChecksum    = QLabel("Checksum", self)
        self.applicationMD5   = QLabel("File Integrity Check", self)
        self.buttonMD5Hash    = QPushButton("Hash",self)
        self.textMD5Plain     = QTextEdit(self)
        self.textMD5Digest    = QTextEdit(self)
        self.comboMD5Mode     = QComboBox(self)
        self.buttonFile       = QPushButton("Choose File", self)
        self.buttonChecksum   = QPushButton("Choose File", self)
        self.buttonGenerate   = QPushButton("Generate", self)
        self.buttonVerify     = QPushButton("Verify", self)


        self.comboMD5Mode.addItem("Generate")
        self.comboMD5Mode.addItem("Verify") 
        self.comboMD5Mode.adjustSize()
        
        self.layoutMD5Button = QVBoxLayout()
        self.layoutMD5Button.setContentsMargins(LEFT, 0, RIGHT, 0)
        self.layoutMD5Button.addStretch()
        self.layoutMD5Button.addWidget(self.buttonMD5Hash)
        self.layoutMD5Button.addStretch()
        
        self.layoutMD5Left = QVBoxLayout()
        self.layoutMD5Left.addWidget(self.labelMD5Plain)
        self.layoutMD5Left.addWidget(self.textMD5Plain)
        
        self.layoutMD5Right = QVBoxLayout()
        self.layoutMD5Right.addWidget(self.labelMD5Digest)
        self.layoutMD5Right.addWidget(self.textMD5Digest)
        
        self.layoutMD5Text = QHBoxLayout()
        self.layoutMD5Text.setContentsMargins(LEFT, TOP, RIGHT, BOTTOM)
        self.layoutMD5Text.addLayout(self.layoutMD5Left)
        self.layoutMD5Text.addLayout(self.layoutMD5Button)
        self.layoutMD5Text.addLayout(self.layoutMD5Right)
       
        # Separator
        self.layoutSeparator = QHBoxLayout()

        self.separatorL = QFrame()
        self.separatorL.setFrameShape(QFrame.HLine)

        self.separatorR = QFrame()
        self.separatorR.setFrameShape(QFrame.HLine) 
        
        self.applicationMD5.setFixedWidth(250)
        self.applicationMD5.setAlignment(Qt.AlignCenter)

        self.layoutSeparator.setContentsMargins(0, TOP, 0, 0)
        self.applicationMD5.setStyleSheet("font-weight: bold;")

        self.layoutSeparator.addWidget(self.separatorL)
        self.layoutSeparator.addWidget(self.applicationMD5)
        self.layoutSeparator.addWidget(self.separatorR)
        

        # Appplication part
        self.layoutChecksumText = QHBoxLayout()
        self.layoutChecksumText.setSpacing(10)
        self.layoutChecksumText.setContentsMargins(0, TOP, 0, BOTTOM)
        self.layoutChecksumText.addStretch()
        self.layoutChecksumText.addWidget(self.comboMD5Mode)
        self.layoutChecksumText.addWidget(self.labelChecksum)
        self.layoutChecksumText.addStretch()
        
        self.layoutFile = QVBoxLayout()

        self.fileLabel = QLabel(self)
        self.fpixmap = QPixmap('attributes/file_not_added.png')
        self.fileLabel.setPixmap(self.fpixmap)
        self.fileLabel.resize(self.fpixmap.width(), self.fpixmap.height() )

        self.layoutFile.addWidget(QLabel("File to Hash:" , self) )
        self.layoutFile.addWidget(self.fileLabel)
        self.layoutFile.addWidget(self.buttonFile)
        
        self.layoutChecksumButton = QVBoxLayout()
        self.layoutChecksumButton.setSpacing(20)
        self.layoutChecksumButton.addStretch()

        self.layoutChecksumButton.addWidget(self.buttonGenerate)
        self.layoutChecksumButton.addWidget(self.buttonVerify)
        self.buttonVerify.setEnabled(False)
        self.layoutChecksumButton.addStretch()
        
        self.layoutChecksum = QVBoxLayout()
        
        self.checksumLabel = QLabel(self)
        self.cpixmap = QPixmap('attributes/file_not_added.png')
        self.checksumLabel.setPixmap(self.cpixmap)
        self.checksumLabel.resize(self.cpixmap.width(), self.cpixmap.height() )

        self.layoutChecksum.addWidget(QLabel("Checksum:", self) )
        self.layoutChecksum.addWidget(self.checksumLabel)
        self.layoutChecksum.addWidget(self.buttonChecksum)
        
        self.layoutMD5Application = QHBoxLayout()
        self.layoutMD5Application.addLayout(self.layoutFile)
        self.layoutMD5Application.addLayout(self.layoutChecksumButton)
        self.layoutMD5Application.addLayout(self.layoutChecksum)

        self.layoutMD5 = QVBoxLayout()
        self.layoutMD5.addLayout(self.layoutMD5Text)
        self.layoutMD5.addLayout(self.layoutSeparator)
        self.layoutMD5.addLayout(self.layoutChecksumText)
        self.layoutMD5.addLayout(self.layoutMD5Application)

        self.tabMD5.setLayout(self.layoutMD5)
        self.buttonMD5Hash.clicked.connect(self._MD5Hash)
        
        # Create RSA tab
        
        self.labelRSAKeyLength    = QLabel("Key length:",self)
        self.labelRSAPrivateKey   = QLabel("Private Key:",self)
        self.labelRSAEulerTotient = QLabel("Euler Totient:",self)
        self.labelRSAPlain        = QLabel("Plain Text:",self)
        self.labelRSACypher       = QLabel("Cipher Text:",self)
        self.buttonRSAEncrypt     = QPushButton("Encrypt",self)
        self.buttonRSADecrypt     = QPushButton("Decrypt",self)
        self.textRSAPlain         = QTextEdit(self)
        self.textRSACypher        = QTextEdit(self)
        self.textRSAKeyLength     = QTextEdit(self)
        self.textRSAPrivateKey = QTextEdit(self)
        self.textRSAEulerTotient=QTextEdit(self)
        
        self.layoutRSAButton = QVBoxLayout()
        self.layoutRSAButton.addStretch()
        self.layoutRSAButton.addWidget(self.buttonRSAEncrypt)
        self.layoutRSAButton.addStretch()
        self.layoutRSAButton.addWidget(self.buttonRSADecrypt)
        self.layoutRSAButton.addStretch()
        
        self.layoutRSALeft = QVBoxLayout()
        self.layoutRSALeft.addWidget(self.labelRSAPlain)
        self.layoutRSALeft.addWidget(self.textRSAPlain)
        
        self.layoutRSARight = QVBoxLayout()
        self.layoutRSARight.addWidget(self.labelRSACypher)
        self.layoutRSARight.addWidget(self.textRSACypher)
        
        self.layoutRSAText = QHBoxLayout()
        self.layoutRSAText.addLayout(self.layoutRSALeft)
        self.layoutRSAText.addLayout(self.layoutRSAButton)
        self.layoutRSAText.addLayout(self.layoutRSARight)
        
        self.layoutRSAKeyLength = QHBoxLayout()
        self.layoutRSAKeyLength.addWidget(self.labelRSAKeyLength)
        self.layoutRSAKeyLength.addWidget(self.textRSAKeyLength)
        
        self.layoutRSAPrivateKey = QHBoxLayout()
        self.layoutRSAPrivateKey.addWidget(self.labelRSAPrivateKey)
        self.layoutRSAPrivateKey.addWidget(self.textRSAPrivateKey)
        
        self.layoutRSAEulerTotient = QHBoxLayout()
        self.layoutRSAEulerTotient.addWidget(self.labelRSAEulerTotient)
        self.layoutRSAEulerTotient.addWidget(self.textRSAEulerTotient)
        
        self.layoutRSAKey = QVBoxLayout()
        self.layoutRSAKey.addLayout(self.layoutRSAKeyLength)
        self.layoutRSAKey.addLayout(self.layoutRSAPrivateKey)
        self.layoutRSAKey.addLayout(self.layoutRSAEulerTotient)
        
        
        self.layoutRSA = QVBoxLayout()
        self.layoutRSA.addLayout(self.layoutRSAKey)
        self.layoutRSA.addLayout(self.layoutRSAText)
        
        self.tabRSA.setLayout(self.layoutRSA)
        
        self.textRSAKeyLength.setFixedHeight(TEXT_HEIGHT)
        self.textRSAPrivateKey.setFixedHeight(TEXT_HEIGHT)
        self.textRSAEulerTotient.setFixedHeight(TEXT_HEIGHT)
        
        self.buttonRSAEncrypt.clicked.connect(self._RSAEncrypt)
        self.buttonRSADecrypt.clicked.connect(self._RSADecrypt) 
             
        # Add tabs to widget        
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)
        
    # Create functions for AES
    def _AESEncrypt(self):
        mode = self.comboAESMode.currentIndex()
        key = self.textAESKey.toPlainText()
        if len(key)>16:
            key = key[:16]
        elif len(key)<16:
            key = key + " "*(16-len(key))
        #print(key)
        cypherKey = []
        for i in key:
            cypherKey.append(ord(i))
        #print(cypherKey)
        
        plainText = self.textAESPlain.toPlainText()
        
        instance = aes.AESModeOfOperation()
        instance.set_key(key)
        initialVector = [103, 35, 148, 239, 76, 213, 47, 118,255, 222, 123, 176, 106, 134, 98, 92]
        
        encodeMode = "OFB"
        if mode == 0: # OFB
            encodeMode = "OFB"
        elif mode == 1: # CFB
            encodeMode = "CFB"
        elif mode == 2: # CBC
            encodeMode = "CBC"
        
        modeAES, lengthAES, cypherText = instance.encrypt(plainText, instance.modeOfOperation[encodeMode], cypherKey, instance.aes.keySize["SIZE_128"], initialVector)
        
        self.textAESCypher.setPlainText("".join(chr(x) for x in cypherText))
        #print(cypherText)
        
    def _AESDecrypt(self):
        mode = self.comboAESMode.currentIndex()
        key = self.textAESKey.toPlainText()
        if len(key)>16:
            key = key[:16]
        elif len(key)<16:
            key = key + " "*(16-len(key))
        cypherKey = []
        for i in key:
            cypherKey.append(ord(i))
        cypherText = self.textAESCypher.toPlainText()
        cypherText2 = []
        for i in cypherText:
            cypherText2.append(ord(i))
        
        #print (cypherText2)
        instance = aes.AESModeOfOperation()
        initialVector = [103, 35, 148, 239, 76, 213, 47, 118,255, 222, 123, 176, 106, 134, 98, 92]

        if mode == 0: # OFB
            encodeMode = "OFB"
        elif mode == 1: # CFB
            encodeMode = "CFB"
        elif mode == 2: # CBC
            encodeMode = "CBC"        
        
        plainText = instance.decrypt(cypherText2, None, mode, cypherKey, instance.aes.keySize["SIZE_128"], initialVector)
        self.textAESPlain.setPlainText(plainText)
        
        
    # Create functions for DES
    def _DESEncrypt(self):
        mode = self.comboDESMode.currentIndex()
        key = self.textDESKey.toPlainText()
        plainText = self.textDESPlain.toPlainText()
        
        if plainText == "": # file encrypt
            if self.filePath:
                start = time.time()
                outputPath = os.path.dirname(self.filePath)
                outputExpand = self.filePath.split(".")[-1]
                outputPath = outputPath + "/encrypted" + "." + outputExpand
                print(outputPath)
                encryptor = file_encryptor.FileEncryptor()
                encryptor.register_plain_source(self.filePath)
                encryptor.register_encrypt_source(outputPath)
                encryptor.set_key(key)
                encryptor.start_encrypt()
                end = time.time()
                msgBox = QMessageBox()
                msgText= "Encrypt complete with " + "{:3f}".format((end-start))+"s"
                msgBox.setText(msgText)
                msgBox.setWindowTitle("Success")
                msgBox.exec()
            else:# No input
                msgBox = QMessageBox()
                msgBox.setText("No input for encrypt")
                msgBox.exec()
        else:
            instance = cryptography_des.CryptographyDES()
            instance.set_work_mode(mode)
            instance.set_plain_text(plainText)
            
            if mode == 0: # ECB
                instance.set_key(key)
                instance.encrypt()
            elif mode == 1: # CBC
                instance.set_key(key)
                vec = instance.get_init_vector()
                instance.encrypt()
                self.textDESInitVec.setPlainText(vec)
            elif mode == 2: # 3 DES
                keys = self.textDESKey.toPlainText().split(" ")
                for key in keys:
                    instance.set_key(key)
                instance.encrypt()
            
            cypherText = instance.get_cipher_text()  
            self.textDESCypher.setPlainText(cypherText)  
            
    def _DESDecrypt(self):
        mode = self.comboDESMode.currentIndex()
        key = self.textDESKey.toPlainText()
        cypherText = self.textDESCypher.toPlainText()

        if cypherText == "": #file encrypt
            if self.filePath:
                start = time.time()
                outputPath = os.path.dirname(self.filePath)
                outputExpand = self.filePath.split(".")[-1]
                outputPath = outputPath + "/decrypted" + "." + outputExpand
                decryptor = file_encryptor.FileEncryptor()
                decryptor.register_encrypt_source(self.filePath)
                decryptor.register_plain_source(outputPath)
                decryptor.set_key(key)
                decryptor.start_decrypt()
                end = time.time()
                msgBox = QMessageBox()
                msgText= "Decrypt complete with " + "{:3f}".format((end-start))+"s"
                msgBox.setText(msgText)
                msgBox.setWindowTitle("Success")
                msgBox.exec()
            else:# No input
                msgBox = QMessageBox()
                msgBox.setText("No input for decrypt")
                msgBox.exec()
        else:
            instance = cryptography_des.CryptographyDES()
            instance.set_work_mode(mode)
            instance.set_cipher_text(cypherText)
            
            if mode == 0: # ECB
                instance.set_key(key)
                instance.decrypt()
            elif mode == 1: # CBC
                instance.set_key(key)
                vec = self.textDESInitVec.toPlainText()
                instance.set_init_vector(vec)
                instance.decrypt()
            elif mode == 2: # 3 DES
                keys = self.textDESKey.toPlainText().split(" ")
                for key in keys:
                    instance.set_key(key)
                instance.decrypt()
            
            plainText = instance.get_plain_text()  
            self.textDESPlain.setPlainText(plainText)

    def _DESEncryptFile(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self,
                      "Choose a file to encrypt", "",
                      "Text Files (*.txt);;Image Files (*.png *.jpg *.bmp);;Video Files (*.mp4 *.avi)", options=options)
        if fileName:
            self.filePath = fileName
            self.labelDESPlainFile.setText(fileName)
    
    def _DESDecryptFile(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self,
                      "Choose a file to decrypt", "",
                      "Text Files (*.txt);;Image Files (*.png *.jpg *.bmp);;Video Files (*.mp4 *.avi)", options=options)
        if fileName:
            self.filePath = fileName
            self.labelDESCypherFile.setText(fileName)

    # Create function for MD5 
    def _MD5Hash(self):
        plainText = self.textMD5Plain.toPlainText()
        instance = cryptography_md5.CryptographyMD5()
        digest = instance.encrypt(plainText)
        self.textMD5Digest.setPlainText(digest)
    
    # Create function for RSA
    def _RSAEncrypt(self):
        plainText = self.textRSAPlain.toPlainText()
        keyLength = self.textRSAKeyLength.toPlainText()
        try:
            keyLength = int(keyLength)
        except ValueError:
            msgBox = QMessageBox()
            msgText= "Invalid Key length!"
            msgBox.setText(msgText)
            msgBox.setWindowTitle("Error")
            msgBox.exec()
            return
        if keyLength < 512:
            msgBox = QMessageBox()
            msgText= "Does not accept key length to be less than 512!"
            msgBox.setText(msgText)
            msgBox.setWindowTitle("Error")
            msgBox.exec()
            return

        instance = cryptography_rsa.CryptographyRSA(key_length=keyLength)
        instance.set_plain_text(plainText)
        instance.set_key(key='initial')
        
        keyChain = instance.get_key()
        privateKey = keyChain["private_key"]
        eulerTotient = keyChain["euler_totient"]
        
        instance.encrypt()
        
        cypherText = instance.get_cipher_text()
        
        self.textRSACypher.setPlainText(cypherText)
        self.textRSAPrivateKey.setPlainText(str(privateKey))
        self.textRSAEulerTotient.setPlainText(str(eulerTotient))
        
    def _RSADecrypt(self):
        cypherText = self.textRSACypher.toPlainText()

        keyLength = self.textRSAKeyLength.toPlainText()
        keyLength = int(keyLength)

        privateKey = self.textRSAPrivateKey.toPlainText()
        privateKey = int(privateKey)

        eulerTotient = self.textRSAEulerTotient.toPlainText()
        eulerTotient = int(eulerTotient)
        
        instance = cryptography_rsa.CryptographyRSA(key_length=keyLength)
        instance.set_key(key='private_key',
                         private_key=privateKey,
                         totient=eulerTotient)
        instance.set_cipher_text(cypherText)
        
        instance.decrypt()
        
        plainText = instance.get_plain_text_as_string()
        self.textRSAPlain.setPlainText(plainText)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    f = app.font();
    f.setFamily(FONT)
    f.setPointSize(14)
    app.setFont(f)
    sys.exit(app.exec_())
