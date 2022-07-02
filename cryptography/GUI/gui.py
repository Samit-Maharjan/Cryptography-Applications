
from ..DES import cryptography_des
from ..DES import file_encryptor
from ..MD5 import cryptography_md5
from ..RSA import cryptography_rsa
from ..AES import aes
from PyQt5.QtWidgets import QWidget, QLabel, QPushButton, QComboBox, QApplication, QTextEdit, QFileDialog, QMainWindow, QApplication, QVBoxLayout, QTabWidget, QHBoxLayout, QSpacerItem, QMessageBox, QGridLayout, QFrame, QSizePolicy, QFormLayout, QRadioButton
from PyQt5.QtCore import pyqtSlot, Qt
from PyQt5.QtGui import QIcon, QFont, QPixmap

import sys
import os
import os.path
import time
sys.path.append(os.path.abspath('../AES'))

INITIAL_WIDTH  = 800
INITIAL_HEIGHT = 800
TEXT_HEIGHT    = 40
FONT = "Consolas"
MODE = "Automatic"

# MARGINS
LEFT = 20
TOP = 20
RIGHT = 20
BOTTOM = 20

CSS = "font-weight: bold; font-size: 20px;"

class App(QMainWindow):
    def __init__(self):
        super().__init__()

        self.title  = 'Applications of Cryptography'
        self.left   = 550
        self.top    = 180
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
        self.labelAESKey      = QLabel(" Key:",self)
        self.labelAESPlain    = QLabel("Plain Text:",self)
        self.labelAESCypher   = QLabel("Cipher Text:",self)
        self.applicationAES   = QLabel("Message Encryption", self)

        self.buttonAESEncrypt = QPushButton("Encrypt\n>>>",self)
        self.buttonAESDecrypt = QPushButton("Decrypt\n<<<",self)
        self.buttonClear      = QPushButton("Clear", self)

        self.buttonServerSend = QPushButton("➤")
        self.buttonClientSend = QPushButton("➤")

        self.labelServer      = QLabel("Server", self)
        self.labelClient      = QLabel("Client", self)
        
        self.textServer       = QTextEdit(self)
        self.textClient       = QTextEdit(self)
        self.textServerSend   = QTextEdit(self)
        self.textClientSend   = QTextEdit(self)
    
        self.textAESPlain     = QTextEdit(self)
        self.textAESCypher    = QTextEdit(self)
        self.textAESKey       = QTextEdit(self)
        self.comboAESMode     = QComboBox(self)
        
        self.comboAESMode.addItem("OFB")
        self.comboAESMode.addItem("CFB")
        self.comboAESMode.addItem("CBC")

        self.textServer.setTextInteractionFlags(Qt.NoTextInteraction)
        self.textClient.setTextInteractionFlags(Qt.NoTextInteraction)

        self.layoutAESButton = QVBoxLayout()
        self.layoutAESButton.setContentsMargins(LEFT, 0, RIGHT, 0)
        self.layoutAESButton.setSpacing(20)

        self.layoutAESButton.addStretch() 
        self.layoutAESButton.addWidget(self.buttonAESEncrypt)
        self.layoutAESButton.addWidget(self.buttonAESDecrypt)
        self.layoutAESButton.addWidget(self.buttonClear)
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
        self.layoutAESKey.addWidget(self.comboAESMode)
        self.layoutAESKey.addWidget(self.labelAESKey)
        self.layoutAESKey.addWidget(self.textAESKey)
        
       
        # Separator
        self.layoutSeparator = QHBoxLayout()
        self.separatorL = QFrame()
        self.separatorL.setFrameShape(QFrame.HLine)
        
        self.separatorR = QFrame()
        self.separatorR.setFrameShape(QFrame.HLine)

        self.applicationAES.setFixedWidth(220)
        self.applicationAES.setAlignment(Qt.AlignCenter)

        self.layoutSeparator.setContentsMargins(0, TOP, 0, BOTTOM * 2)
        self.applicationAES.setStyleSheet(CSS) 

        self.layoutSeparator.addWidget(self.separatorL)
        self.layoutSeparator.addWidget(self.applicationAES)
        self.layoutSeparator.addWidget(self.separatorR)

        #Application Part

        self.layoutApplication = QHBoxLayout()

        self.ServerSend = QHBoxLayout()
        self.ServerSend.addWidget(self.textServerSend)
        self.ServerSend.addWidget(self.buttonServerSend)

        self.ClientSend = QHBoxLayout()
        self.ClientSend.addWidget(self.textClientSend)
        self.ClientSend.addWidget(self.buttonClientSend)

        self.layoutServer = QVBoxLayout()
        self.layoutServer.setSpacing(20)
        self.layoutServer.setContentsMargins(LEFT, 0, RIGHT, BOTTOM)
        self.layoutServer.addWidget(self.labelServer)        
        self.layoutServer.addWidget(self.textServer)
        self.layoutServer.addLayout(self.ServerSend)

        self.layoutClient = QVBoxLayout()
        self.layoutClient.setSpacing(20)
        self.layoutClient.setContentsMargins(LEFT, 0, RIGHT, BOTTOM)
        self.layoutClient.addWidget(self.labelClient)        
        self.layoutClient.addWidget(self.textClient)
        self.layoutClient.addLayout(self.ClientSend)
        
        self.layoutApplication.addLayout(self.layoutServer)
        self.layoutApplication.addLayout(self.layoutClient)

        self.layoutAES = QVBoxLayout()
        self.layoutAES.addLayout(self.layoutAESKey)
        self.layoutAES.addLayout(self.layoutAESText)
        self.layoutAES.addLayout(self.layoutSeparator)
        self.layoutAES.addLayout(self.layoutApplication)
       

        self.tabAES.setLayout(self.layoutAES)
        self.textAESKey.setFixedHeight(TEXT_HEIGHT) 
        self.textServerSend.setFixedHeight(TEXT_HEIGHT)
        self.textClientSend.setFixedHeight(TEXT_HEIGHT)

        self.buttonAESEncrypt.clicked.connect(lambda : self._AES(1) )
        self.buttonAESDecrypt.clicked.connect(lambda : self._AES(0) )

        self.buttonServerSend.clicked.connect(lambda : self._AESApp(1) )
        self.buttonClientSend.clicked.connect(lambda : self._AESApp(0) )
        self.buttonClear.clicked.connect(lambda : 
                self.textAESCypher.setPlainText("") or
                self.textAESPlain.setPlainText("")  or
                self.textServer.setPlainText("")    or
                self.textClient.setPlainText("") )

        # Create DES tab
        
        self.labelDESKey          = QLabel("  Key:",self)
        self.labelDESPlain        = QLabel("Plain Text:",self)
        self.labelDESCypher       = QLabel("Cipher Text:",self)
        self.labelDESInitVec      = QLabel("Initial vector:",self)
        self.labelDESPlainFile    = QLabel("", self)
        self.labelDESCypherFile   = QLabel("", self) 
        self.labelInputFile       = QLabel("", self)
        self.labelOutputFile      = QLabel("", self)
        self.applicationDES       = QLabel("File Encryption/Decryption", self)
        self.labelStatus          = QLabel("", self)   

        self.buttonDESEncrypt     = QPushButton("Encrypt\n>>>",self)
        self.buttonDESDecrypt     = QPushButton("Decrypt\n<<<",self)
        self.buttonDESEncryptFile = QPushButton("Encrypt File",self)
        self.buttonDESDecryptFile = QPushButton("Decrypt File",self)
        self.buttonInput          = QPushButton("Choose File", self)
        self.buttonClear          = QPushButton("Clear", self)

        self.textDESPlain         = QTextEdit(self)
        self.textDESCypher        = QTextEdit(self)
        self.textDESKey           = QTextEdit(self)
        self.textDESInitVec       = QTextEdit(self)

        self.comboDESMode         = QComboBox(self)
        self.comboDES             = QComboBox(self)
        
        self.comboDESMode.addItem("ECB")
        self.comboDESMode.addItem("CBC")
        self.comboDESMode.addItem("3-DES")
        
        self.comboDES.addItem("Encrypt")
        self.comboDES.addItem("Decrypt")
        
        self.layoutDESKeyMode = QHBoxLayout()
        self.layoutDESKeyMode.addWidget(self.comboDESMode)
        self.layoutDESKeyMode.addWidget(self.labelDESKey)
        self.layoutDESKeyMode.addWidget(self.textDESKey)

        self.layoutDESInitVec = QHBoxLayout()
        self.layoutDESInitVec.addWidget(self.labelDESInitVec)
        self.layoutDESInitVec.addWidget(self.textDESInitVec)

        self.layoutDESKey = QVBoxLayout()
        self.layoutDESKey.setContentsMargins(LEFT, 0, RIGHT, BOTTOM)
        self.layoutDESKey.addLayout(self.layoutDESInitVec)
        self.layoutDESKey.addLayout(self.layoutDESKeyMode)

        self.layoutDESButton = QVBoxLayout()
        self.layoutDESButton.setSpacing(20)
        self.layoutDESButton.setContentsMargins(LEFT, TOP * 3, RIGHT, BOTTOM)
        self.layoutDESButton.addStretch()
        self.layoutDESButton.addWidget(self.buttonDESEncrypt)
        self.layoutDESButton.addWidget(self.buttonDESDecrypt)
        self.layoutDESButton.addWidget(self.buttonClear)
        self.layoutDESButton.addStretch()

    
        self.layoutDESLeft = QVBoxLayout()
        self.layoutDESLeft.setContentsMargins(LEFT, 0, RIGHT, BOTTOM - 5)
        self.layoutDESLeft.addWidget(self.labelDESPlain)
        self.layoutDESLeft.addWidget(self.textDESPlain)
        
        self.layoutDESRight = QVBoxLayout()
        self.layoutDESRight.setContentsMargins(LEFT, 0, RIGHT, BOTTOM - 5)
        self.layoutDESRight.addWidget(self.labelDESCypher)
        self.layoutDESRight.addWidget(self.textDESCypher)
        
        self.layoutDESText = QHBoxLayout()
        self.layoutDESText.addLayout(self.layoutDESLeft)
        self.layoutDESText.addLayout(self.layoutDESButton)
        self.layoutDESText.addLayout(self.layoutDESRight)  
        
        # Separator
        self.layoutSeparator = QHBoxLayout()
        self.separatorL = QFrame()
        self.separatorL.setFrameShape(QFrame.HLine)
        
        self.separatorR = QFrame()
        self.separatorR.setFrameShape(QFrame.HLine)

        self.applicationDES.setFixedWidth(310)
        self.applicationDES.setAlignment(Qt.AlignCenter)

        self.layoutSeparator.setContentsMargins(0, TOP, 0, BOTTOM * 2)
        self.applicationDES.setStyleSheet(CSS)
        
        self.layoutSeparator.addWidget(self.separatorL)
        self.layoutSeparator.addWidget(self.applicationDES)
        self.layoutSeparator.addWidget(self.separatorR)
        

        #Application
        self.layoutApplication = QHBoxLayout()
        self.layoutApplication.setSpacing(50)
        self.layoutApplication.setContentsMargins(LEFT, TOP, RIGHT, BOTTOM)
        self.layoutApplication.addWidget(QLabel("INPUT:", self) )

        self.layoutEncOrDec = QHBoxLayout()
        self.layoutEncOrDec.setSpacing(10)
        self.layoutEncOrDec.addWidget(self.comboDES)
        self.layoutEncOrDec.addWidget(QLabel("File", self) )
        self.layoutEncOrDec.setAlignment(Qt.AlignCenter)
        
        self.layoutApplication.addLayout(self.layoutEncOrDec)
        self.layoutApplication.addWidget(QLabel("OUTPUT:", self) )
        self.layoutApplication.setContentsMargins(LEFT, 0, RIGHT, 0)
            
        self.layoutFileInput = QVBoxLayout()
        self.layoutFileInput.setContentsMargins(LEFT, TOP, RIGHT, BOTTOM)
        self.layoutFileInput.addWidget(self.labelInputFile)
        self.layoutFileInput.addWidget(self.buttonInput)

        self.layoutFileButton = QVBoxLayout()
        self.layoutFileButton.setSpacing(20)
        self.layoutFileButton.setContentsMargins(LEFT, TOP * 2, RIGHT, BOTTOM)
        self.layoutFileButton.setAlignment(Qt.AlignCenter)

        self.buttonDESEncryptFile.setFixedWidth(160)
        self.layoutFileButton.addWidget(self.buttonDESEncryptFile)
        self.buttonDESDecryptFile.setFixedWidth(160)
        self.layoutFileButton.addWidget(self.buttonDESDecryptFile)

        self.layoutFileButton.addWidget(self.labelStatus)
        
        #By default in Encrypt Mode
        self.buttonDESDecryptFile.setEnabled(False)

        self.layoutFileOutput = QVBoxLayout()
        self.layoutFileOutput.setContentsMargins(LEFT, TOP, RIGHT, BOTTOM)
        self.layoutFileOutput.addWidget(self.labelOutputFile)
        
        self.layoutApplicationDES = QHBoxLayout()
        self.layoutApplicationDES.addLayout(self.layoutFileInput)
        self.layoutApplicationDES.addLayout(self.layoutFileButton)
        self.layoutApplicationDES.addLayout(self.layoutFileOutput)        

        self.layoutDES = QVBoxLayout()
        self.layoutDES.addLayout(self.layoutDESKey)
        self.layoutDES.addLayout(self.layoutDESText)
        self.layoutDES.addLayout(self.layoutSeparator)
        self.layoutDES.addLayout(self.layoutApplication)
        self.layoutDES.addLayout(self.layoutApplicationDES)
        
        self.tabDES.setLayout(self.layoutDES)
        self.textDESKey.setFixedHeight(TEXT_HEIGHT) 
        self.textDESInitVec.setFixedHeight(TEXT_HEIGHT)
        
        self.buttonDESEncrypt.clicked.connect(lambda : self._DES(1) )
        self.buttonDESDecrypt.clicked.connect(lambda : self._DES(0) )
        self.buttonInput.clicked.connect(self._DESFileChoose)
        self.buttonDESEncryptFile.clicked.connect(lambda : self._DESFile(1) )
        self.buttonDESDecryptFile.clicked.connect(lambda : self._DESFile(0) )
        self.buttonClear.clicked.connect(lambda:
                self.textDESPlain.setPlainText("")  or
                self.textDESCypher.setPlainText("") or
                self.labelInputFile.setText("") )

        # Create MD5 tab
        
        self.labelMD5Plain    = QLabel("Plain Text:",self)
        self.labelMD5Digest   = QLabel("Digest Text:",self)
        self.labelChecksum    = QLabel("Checksum", self)
        self.applicationMD5   = QLabel("File Integrity Check", self)
        self.buttonMD5Hash    = QPushButton("Hash\n>>>",self)
        self.textMD5Plain     = QTextEdit(self)
        self.textMD5Digest    = QTextEdit(self)
        self.comboMD5Mode     = QComboBox(self)
        self.buttonFile       = QPushButton("Choose File", self)
        self.buttonChecksum   = QPushButton("Choose File", self)
        self.buttonGenerate   = QPushButton("Generate", self)
        self.buttonVerify     = QPushButton("Verify", self)
        self.labelPlainFile   = QLabel("", self)
        self.labelChecksumFile= QLabel("", self)
        self.labelStatus      = QLabel("", self)

        self.comboMD5Mode.addItem("Generate")
        self.comboMD5Mode.addItem("Verify") 
        
        self.layoutMD5Button = QVBoxLayout()
        self.layoutMD5Button.setContentsMargins(LEFT, 0, RIGHT, 0)
        self.layoutMD5Button.addWidget(self.buttonMD5Hash)
        
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
        
        self.applicationMD5.setFixedWidth(240)
        self.applicationMD5.setAlignment(Qt.AlignCenter)

        self.layoutSeparator.setContentsMargins(0, TOP, 0, BOTTOM)
        self.applicationMD5.setStyleSheet(CSS)

        self.layoutSeparator.addWidget(self.separatorL)
        self.layoutSeparator.addWidget(self.applicationMD5)
        self.layoutSeparator.addWidget(self.separatorR)
        

        # Appplication part
        self.layoutChecksumText = QHBoxLayout()
        self.layoutChecksumText.setSpacing(50)
        self.layoutChecksumText.setContentsMargins(LEFT, TOP, RIGHT, BOTTOM)
        self.layoutChecksumText.addWidget(QLabel("File to Hash:", self) )

        self.layoutGenOrVerify = QHBoxLayout()
        self.layoutGenOrVerify.setSpacing(10)
        self.layoutGenOrVerify.addWidget(self.comboMD5Mode)
        self.layoutGenOrVerify.addWidget(self.labelChecksum)
        self.layoutGenOrVerify.setAlignment(Qt.AlignCenter)

        self.layoutChecksumText.addLayout(self.layoutGenOrVerify)
        self.layoutChecksumText.addWidget(QLabel("Checksum:" , self) ) 
        
        self.layoutFile = QVBoxLayout()
        self.layoutFile.setContentsMargins(LEFT, TOP, RIGHT, BOTTOM)
        self.layoutFile.addWidget(self.labelPlainFile)
        self.layoutFile.addWidget(self.buttonFile)
        
        self.layoutChecksumButton = QVBoxLayout()
        self.layoutChecksumButton.setSpacing(20)
        self.layoutChecksumButton.setContentsMargins(LEFT * 3, TOP, RIGHT * 3, BOTTOM)
        self.buttonGenerate.setFixedWidth(120)
        self.layoutChecksumButton.addWidget(self.buttonGenerate)
        self.buttonVerify.setFixedWidth(120)
        self.layoutChecksumButton.addWidget(self.buttonVerify)
        self.layoutChecksumButton.addWidget(self.labelStatus)

        self.layoutChecksumButton.setAlignment(Qt.AlignCenter)
        # By default in Generate Checksum
        self.buttonVerify.setEnabled(False)
        
        self.layoutChecksum = QVBoxLayout()       
        self.layoutChecksum.setContentsMargins(LEFT, TOP, RIGHT, BOTTOM)
        self.layoutChecksum.addWidget(self.labelChecksumFile)
        self.layoutChecksum.addWidget(self.buttonChecksum)
        
        # By default in Generate Checksum
        self.buttonChecksum.setEnabled(False)
        
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
        
        self.labelRSAp            = QLabel("P:")
        self.labelRSAq            = QLabel("Q:")
        self.labelRSAPublicKey    = QLabel("Public Key:")
        self.labelRSAPrivateKey   = QLabel("Private Key:")
        self.labelRSAPlain        = QLabel("Plain Text:", self)
        self.labelRSACypher       = QLabel("Cipher Text:",self)
        self.labelRSAApplication  = QLabel("Github Remote Login", self)
        self.labelRSAStatus       = QLabel("", self)

        self.textRSAp             = QTextEdit(self)
        self.textRSAq             = QTextEdit(self)
        self.textRSAPublicKey     = QTextEdit(self)
        self.textRSAPrivateKey    = QTextEdit(self)

        self.textRSAPlain         = QTextEdit(self)
        self.textRSACypher        = QTextEdit(self) 
        self.textRSAPkKey         = QTextEdit(self)
        self.textRSAPuKey         = QTextEdit(self)
        

        # self.labelRSAKeyLength    = QLabel("Key length:",self)
        # self.labelRSAPrivateKey   = QLabel("Private Key:",self)
        # self.labelRSAEulerTotient = QLabel("Euler Totient:",self)

        self.buttonRSAEncrypt     = QPushButton("Encrypt",self)
        self.buttonRSADecrypt     = QPushButton("Decrypt",self)
        self.buttonGenerateKey    = QPushButton("Generate Key", self)
        self.buttonGenerateRSAKey = QPushButton("Generate Key", self)
        self.buttonCopyKey        = QPushButton("Copy to Clipboard", self)
        self.buttonConnect        = QPushButton("Connect Github", self)

        # self.textRSAKeyLength     = QTextEdit(self)
        # self.textRSAPrivateKey    = QTextEdit(self)
        # self.textRSAEulerTotient  = QTextEdit(self)
        
        self.layoutRSAButton = QVBoxLayout()
        self.layoutRSAButton.setSpacing(20)
        self.layoutRSAButton.setContentsMargins(LEFT, TOP * 3, RIGHT, BOTTOM)
        self.layoutRSAButton.addStretch()
        self.layoutRSAButton.addWidget(self.buttonRSAEncrypt)
        self.layoutRSAButton.addWidget(self.buttonRSADecrypt)
        self.layoutRSAButton.addStretch()
        
        self.layoutRSAMode = QHBoxLayout()
        self.layoutRSAMode.addWidget(QLabel("Mode:", self))
        self.radioButton = QRadioButton("Automatic")
        self.radioButton.setChecked(True)
        self.radioButton.toggled.connect(self.onClicked)
        self.radioButton.mode = "Automatic"
        self.layoutRSAMode.addWidget(self.radioButton)

        self.radioButton = QRadioButton("Manual")
        self.radioButton.toggled.connect(self.onClicked)
        self.radioButton.mode = "Manual"
        self.layoutRSAMode.addWidget(self.radioButton)

        self.layoutRSAMode.addWidget(QLabel("   ", self) )
        self.layoutRSAMode.addWidget(self.buttonGenerateKey)
        self.layoutRSAMode.addStretch()

        self.layoutRSAMode.setSpacing(20)
        self.layoutRSAMode.setContentsMargins(LEFT, TOP, RIGHT, BOTTOM)
        
        self.layoutRSAValues = QGridLayout()
        self.layoutRSAValues.setSpacing(15)
        self.layoutRSAValues.setContentsMargins(LEFT, 0, RIGHT, BOTTOM)

        self.layoutRSAValues.addWidget(self.labelRSAp, 0, 0)
        self.labelRSAp.setAlignment(Qt.AlignRight)
        self.layoutRSAValues.addWidget(self.textRSAp, 0, 1)

        self.layoutRSAValues.addWidget(self.labelRSAq, 0, 2)
        self.labelRSAq.setAlignment(Qt.AlignRight)
        self.layoutRSAValues.addWidget(self.textRSAq, 0, 3)

        self.layoutRSAValues.addWidget(self.labelRSAPublicKey, 1, 0)  
        self.layoutRSAValues.addWidget(self.textRSAPublicKey, 1, 1)

        self.layoutRSAValues.addWidget(self.labelRSAPrivateKey, 1, 2)
        self.layoutRSAValues.addWidget(self.textRSAPrivateKey, 1, 3)

        # By default in Automatic Mode
        self.textRSAp.setTextInteractionFlags(Qt.NoTextInteraction)
        self.textRSAq.setTextInteractionFlags(Qt.NoTextInteraction)

        # Never Interact
        self.textRSAPublicKey.setTextInteractionFlags(Qt.NoTextInteraction)
        self.textRSAPrivateKey.setTextInteractionFlags(Qt.NoTextInteraction)


        # self.layoutRSAButton = QVBoxLayout()
        # self.layoutRSAButton.addStretch()
        # self.layoutRSAButton.addWidget(self.buttonRSAEncrypt)
        # self.layoutRSAButton.addStretch()
        # self.layoutRSAButton.addWidget(self.buttonRSADecrypt)
        # self.layoutRSAButton.addStretch()
        
        self.layoutRSALeft = QVBoxLayout()
        self.layoutRSALeft.setContentsMargins(LEFT, 0, RIGHT, BOTTOM - 5)
        self.layoutRSALeft.addWidget(self.labelRSAPlain)
        self.layoutRSALeft.addWidget(self.textRSAPlain)
        
        self.layoutRSARight = QVBoxLayout()
        self.layoutRSARight.setContentsMargins(LEFT, 0, RIGHT, BOTTOM - 5)
        self.layoutRSARight.addWidget(self.labelRSACypher)
        self.layoutRSARight.addWidget(self.textRSACypher)
        
        self.layoutRSAText = QHBoxLayout()
        self.layoutRSAText.addLayout(self.layoutRSALeft)
        self.layoutRSAText.addLayout(self.layoutRSAButton)
        self.layoutRSAText.addLayout(self.layoutRSARight)
       
        # Separator
        self.layoutSeparator = QHBoxLayout()
        self.separatorL = QFrame()
        self.separatorL.setFrameShape(QFrame.HLine)
        
        self.separatorR = QFrame()
        self.separatorR.setFrameShape(QFrame.HLine)

        self.labelRSAApplication.setFixedWidth(230)
        self.labelRSAApplication.setAlignment(Qt.AlignCenter)

        self.layoutSeparator.setContentsMargins(0, TOP, 0, BOTTOM)
        self.labelRSAApplication.setStyleSheet(CSS)
        
        self.layoutSeparator.addWidget(self.separatorL)
        self.layoutSeparator.addWidget(self.labelRSAApplication)
        self.layoutSeparator.addWidget(self.separatorR) 

        self.layoutKeyGen = QGridLayout()
        self.layoutKeyGen.setSpacing(20)
        self.layoutKeyGen.setContentsMargins(LEFT, TOP, RIGHT, BOTTOM)

        self.layoutKeyGen.addWidget(self.buttonGenerateRSAKey, 0, 0, 1, 2, Qt.AlignCenter)    

        self.layoutKeyGen.addWidget(QLabel("Private Key:", self), 1, 0, Qt.AlignCenter)
        self.layoutKeyGen.addWidget(QLabel("Public Key:", self), 1, 1, Qt.AlignCenter)
        self.layoutKeyGen.addWidget(self.textRSAPkKey, 2, 0)
        self.layoutKeyGen.addWidget(self.textRSAPuKey, 2, 1)

        self.textRSAPkKey.setTextInteractionFlags(Qt.NoTextInteraction)
        self.textRSAPuKey.setTextInteractionFlags(Qt.NoTextInteraction)


        self.layoutConnect = QVBoxLayout()
        self.layoutConnect.setSpacing(20)
        self.layoutConnect.setContentsMargins(LEFT * 3, TOP * 7, RIGHT * 3, BOTTOM)
        self.layoutConnect.addWidget(self.buttonCopyKey)
        self.layoutConnect.addWidget(self.buttonConnect)
        self.layoutConnect.addWidget(self.labelRSAStatus)

        self.layoutApplication = QHBoxLayout()
        self.layoutApplication.addLayout(self.layoutKeyGen)

        self.layoutApplication.addLayout(self.layoutConnect)
        
        # self.layoutRSAKeyLength = QHBoxLayout()
        # self.layoutRSAKeyLength.addWidget(self.labelRSAKeyLength)
        # self.layoutRSAKeyLength.addWidget(self.textRSAKeyLength)
        
        # self.layoutRSAPrivateKey = QHBoxLayout()
        # self.layoutRSAPrivateKey.addWidget(self.labelRSAPrivateKey)
        # self.layoutRSAPrivateKey.addWidget(self.textRSAPrivateKey)
        
        # self.layoutRSAEulerTotient = QHBoxLayout()
        # self.layoutRSAEulerTotient.addWidget(self.labelRSAEulerTotient)
        # self.layoutRSAEulerTotient.addWidget(self.textRSAEulerTotient)
        
        # self.layoutRSAKey = QVBoxLayout()
        # self.layoutRSAKey.addLayout(self.layoutRSAKeyLength)
        # self.layoutRSAKey.addLayout(self.layoutRSAPrivateKey)
        # self.layoutRSAKey.addLayout(self.layoutRSAEulerTotient)
        
        
        self.layoutRSA = QVBoxLayout()
        self.layoutRSA.addLayout(self.layoutRSAMode)
        self.layoutRSA.addLayout(self.layoutRSAValues)
        self.layoutRSA.addLayout(self.layoutRSAText)
        self.layoutRSA.addLayout(self.layoutSeparator)
        self.layoutRSA.addLayout(self.layoutApplication)

        self.tabRSA.setLayout(self.layoutRSA)
        
        self.buttonGenerateKey.setFixedWidth(180)
        self.buttonGenerateRSAKey.setFixedWidth(180)

        # self.textRSAPuKey.setFixedWidth(250)
        # self.textRSAPkKey.setFixedWidth(250)

        self.buttonCopyKey.setFixedWidth(250)
        self.buttonConnect.setFixedWidth(250)

        self.textRSAp.setFixedHeight(TEXT_HEIGHT)
        self.textRSAq.setFixedHeight(TEXT_HEIGHT)
        self.textRSAPublicKey.setFixedHeight(TEXT_HEIGHT)
        self.textRSAPrivateKey.setFixedHeight(TEXT_HEIGHT)

#        self.textRSAKeyLength.setFixedHeight(TEXT_HEIGHT)
#        self.textRSAPrivateKey.setFixedHeight(TEXT_HEIGHT)
#        self.textRSAEulerTotient.setFixedHeight(TEXT_HEIGHT)
        
#        self.buttonRSAEncrypt.clicked.connect(self._RSAEncrypt)
#        self.buttonRSADecrypt.clicked.connect(self._RSADecrypt) 
             
        # Add tabs to widget        
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout)
        

    # Radio Button Clicked
    def onClicked(self):
        self.radioButton = self.sender()
        if(self.radioButton.isChecked() ):
            MODE = self.radioButton.mode


    # Create functions for AES
    def _AESApp(self, server):
        serverText = self.textServerSend.toPlainText()
        clientText  = self.textClientSend.toPlainText() 

        if server == 1:
            self.textServerSend.setPlainText("")
            print("Server:")
            print("Message from Server: ", self._AESEncrypt(serverText) )
            self._server(serverText, 1, 0) 

        else:
            self.textClientSend.setPlainText("")
            print("Client:")
            print("Message from Client: ", self._AESEncrypt(clientText) )
            self._client(clientText, 0, 1)

    def _server(self, serverText, server = 0, client = 0):
        if client:
            print("Server:")
            print("Message received from Client: ", serverText)
            print("Message decrypted in Server: ", self._AESDecrypt(serverText), "\n")
            self.textServer.append("Client: " + self._AESDecrypt(serverText) + "\n")

        else:
            self.textServer.append("Server: " + serverText + "\n")
        if server: 
            self._client(self._AESEncrypt(serverText), 1, 0)

    def _client(self, clientText, server = 0, client = 0):
        if server:
            print("Client:")
            print("Message received from Server: ", clientText)
            print("Message decrypted in Client: ", self._AESDecrypt(clientText), "\n")
            self.textClient.append("Server: " + self._AESDecrypt(clientText) + "\n")
        else:
            self.textClient.append("Client: " + clientText + "\n")
        if client: 
            self._server(self._AESEncrypt(clientText), 0, 1)


    def _AES(self, encrypt:int):
        if encrypt == 1:
            text = self.textAESPlain.toPlainText()
            cypherText = self._AESEncrypt(text)
            self.textAESCypher.setPlainText(cypherText)

        else:
            text = self.textAESCypher.toPlainText()
            plainText = self._AESDecrypt(text)
            self.textAESPlain.setPlainText(self._AESDecrypt(text) )
            

    def _AESEncrypt(self, plainText):
        mode = self.comboAESMode.currentIndex()
        key = self.textAESKey.toPlainText()
        if len(key) > 16:
            key = key[:16]
        
        # padding with whitespaces
        elif len(key) < 16:
            key = key + " " * (16 - len(key) )
        
        # cipherkey with Unicode value of key
        cypherKey = []
        for i in key:
            cypherKey.append(ord(i))
        
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

        return "".join(chr(x) for x in cypherText)  
        
    def _AESDecrypt(self, cypherText):
        mode = self.comboAESMode.currentIndex()
        key = self.textAESKey.toPlainText()
        if len(key) > 16:
            key = key[:16]

        # padding with whitespace
        elif len(key) < 16:
            key = key + " " * (16 - len(key))
        cypherKey = []
        
        # cipherkey from Unicode value of Key
        for i in key:
            cypherKey.append(ord(i))
        
        # Unicode values of Cipher text
        cypherTextASCII = []
        for i in cypherText:
            cypherTextASCII.append(ord(i))
        
        instance = aes.AESModeOfOperation()
        initialVector = [103, 35, 148, 239, 76, 213, 47, 118,255, 222, 123, 176, 106, 134, 98, 92]

        if mode == 0: # OFB
            encodeMode = "OFB"
        elif mode == 1: # CFB
            encodeMode = "CFB"
        elif mode == 2: # CBC
            encodeMode = "CBC"        
        
        plainText = instance.decrypt(cypherTextASCII, None, mode, cypherKey, instance.aes.keySize["SIZE_128"], initialVector)
        return plainText
        
    # Create functions for DES
    def _DES(self, encrypt):
        if encrypt == 1:
            text = self.textDESPlain.toPlainText()
            cypherText = self._DESEncrypt(text)
            self.textDESCypher.setPlainText(cypherText)

        else:
            text = self.textDESCypher.toPlainText()
            plainText = self._DESDecrypt(text)
            self.textDESPlain.setPlainText(plainText)
            
    def _DESFile(self, encrypt):
        if encrypt == 1:
            self._DESEncryptFile()
        else:
            self._DESDecryptFile()

    def _DESEncrypt(self, plainText):
        mode = self.comboDESMode.currentIndex()
        key = self.textDESKey.toPlainText()
        
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
        return cypherText
            
    def _DESDecrypt(self, cypherText):
        mode = self.comboDESMode.currentIndex()
        key = self.textDESKey.toPlainText()

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
        return plainText

    def _DESFileChoose(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self,
                      "Open File", "",
                      "All Files (*)", options = options)
        if fileName:
            self.filePath = fileName
            fileIndex = fileName.rindex("/")
            parentIndex = fileName[:fileIndex].rindex("/")
            self.labelInputFile.setText("..." + fileName[parentIndex : ])

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
