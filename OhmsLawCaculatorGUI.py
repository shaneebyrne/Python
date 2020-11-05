from Tkinter import * 
import Tkinter as tk
from Intensity import Current as c
from Voltage import Emf as v
from Resistance import Impediance as r  
from Wattage import  Power as w
from OhmsLaw import Ohm as cal
#from PIL import  ImageTK
#from PIL import Image



def main():

    gui = tk.Tk()

    frame = tk.Frame(gui)


    tk.Label(frame, text = "Enter Appropriate Data to perform calculation: ", font=("Helvetica", "16"), bg="White", bd=20,anchor=W,height=3,width=40).grid(row=0)

    #tk.Label.config(font=("Courier",44))

    frame.configure(bg="Brown")

    path = "volt.gif"

    #img = ImageTk.PhotoImage(Image.open(path))

    tk.Label(frame, text="Voltage: ", font=("Helvetica", "16"),  bg="White",bd=20,anchor=W, height=3,width=10).grid(row=2)

    #tk.Label(frame, image=img)

    voltEntry = tk.Entry(frame).grid(row=2, column=1)

    #voltEntry.grid(row=2, column=1)

    tk.Label(frame, text = "Current:", font=("Helvetica", "16"),  bg="White",bd=20,anchor=W,height=3,width=10).grid(row=6)

    ampEntry = tk.Entry(frame).grid(row=6, column=1)

    #ampEntry.grid(row=6, column=1)

    tk.Label(frame, text = "Resistance:",font=("Helvetica", "16"),  bg="White",bd=20,anchor=W,height=3,width=10).grid(row=10)

    resisEntry = tk.Entry(frame).grid(row=10, column=1)
    #resisEntry.grid(row=10, column=1)
    
    #selection = voltEntry.get()

    tk.Button(frame, text = "Equals", bg="Green", fg="Black", font=("Helvetica", "16",)).grid(row=16, column=0) #Event Listener needed

    tk.Button(frame, text = "Reset", bg="Yellow",fg="Black", font=("Helvetica", "16")). grid(row=16,column=1) 

    tk.Button(frame, text = "Exit", command=gui.quit, bg="Black", fg="White", font=("Helvetica", "16")). grid(row=16,column=2) 

    gui.title("Ohm's Law Calculator")

    gui.geometry("700x600")


    frame.pack()
    frame.mainloop()
    
def voltButton(self, value):
    self.value = value
    v(value)
    return v.getVoltage()

def ampButton(self, value):
    self.value = value
    c(value)
    return c.getCurrent()

def resisButton(self, value):
    self.value = value
    r(value)
    return r.getResistance()
    
def equals(self, numOne, numTwo, choice):
    
    if choice == 1:
        #Calculates voltage using OhmsLaw method calcVolt
        v.setVoltage(cal.calcVolt(numOne, numTwo))
        return v.getVoltage()
    elif choice == 2:  
        c.setCurrent(cal.calcCurrent(numOne, numTwo))
        return v.getVoltage()
    elif choice == 3:
        r.setResistance(cal.calcResistance(numOne, numTwo))
        return r.getResistance()
    elif choice == 4:         
        w.setWatt(cal.calcWattageVA(v.getVoltage(), c.getAmp()))
        return w.getWatt()
    elif choice == 5:
        w.setWatt(cal.calcWattageAR(c.getAmp(), r.getResistance()))
        return w.getWatt()
    elif choice == 6:
        w.setWatt(cal.wattageVR(v.getVoltage(), r.getResistance()))
        return w.getWatt()


        
if __name__ == "__main__":
    main()