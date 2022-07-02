from PyQt5.QtWidgets import * 
from PyQt5.QtGui import * 
import sys
  
  
class Window(QMainWindow):
    def __init__(self):
        super().__init__()
  
        # set the title
        self.setWindowTitle("Label")
  
        # setting  the geometry of window
        self.setGeometry(0, 0, 400, 300)
  
        # creating a label widget
        # by default label will display at top left corner
        self.label_1 = QLabel('Light green', self)
  
        # moving position
        self.label_1.move(100, 100)
  
        # setting up background color
        self.label_1.setStyleSheet("background-color: lightgreen; color: black")
  
        # creating a label widget
        # by default label will display at top left corner
        self.label_2 = QLabel('Ye', self)
        self.label_2.resize(10, 10)
          
        # moving position
        self.label_2.move(100, 150)
  
        # setting up background color and border
        self.label_2.setStyleSheet("background-color: yellow; border: 1px solid black; color:black")
  
        # show all the widgets
        self.show()
  
  
# create pyqt5 app
App = QApplication(sys.argv)
  
# create the instance of our Window
window = Window()
# start the app
sys.exit(App.exec())
