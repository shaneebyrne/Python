# https://sebsauvage.net/python/gui/#import
from tkinter import *

class gui(Tkinter.Tk):
    Tkinter.Tk.__init__(self,parent)
    self.parent = parent
    self.initialze()

    def initialize():
        self.grid()
        self.entry = Tkinter.Entry(self)
        self.entry.grid(column=0, row=0, sticky='EW')
        button = Tkinter.Button(self,text = u"Click Here!")
        button.gui(column=1,row=0)
        label.Tkinter.Label(self,anchor = "w",fg="white",bg="blue")
        label.grid(column=0, row=1, columnspan=2, sticky = 'EW')


if __name == "__main__":
    app = gui(None)
    app.title('GUI Demo')
    app.mainloop()