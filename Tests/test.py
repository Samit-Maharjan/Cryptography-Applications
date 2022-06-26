import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import Qt

class App(QWidget):

    def __init__(self):
        super().__init__()
        self.title = 'PyQt5 image - pythonspot.com'
        self.left = 10
        self.top = 10
        self.width = 640
        self.height = 480
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)
    
        self.layout = QVBoxLayout()
        # Create widget
        Label = QLabel("File To Add", self)
        Label.setAlignment(Qt.AlignCenter)
        label = QLabel(self)
        pixmap = QPixmap('file_not_added.png')
        label.setPixmap(pixmap)
        self.layout.addWidget(label)
        self.layout.addWidget(Label)
        self.resize(pixmap.width(),pixmap.height())
        self.setLayout(self.layout)
        self.show()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())

