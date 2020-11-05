from Tkinter import * 
import Tkinter as tk
fields = ('VOLTAGE', 'CURRENT', 'RESISTANCE')

def calculate(entries):
   
   v = float(entries['VOLTAGE'].get())
   i =  float(entries['CURRENT'].get())
   
   r = (v/i)
   r = ("%8.2f" % r).strip()
   entries['RESISTANCE'].delete(0,END)
   entries['RESISTANCE'].insert(0, r )
   print("RESISTANCE: %f" % r)



def clear(entries):
    entries['RESISTANCE'].delete(0,END)
    entries['VOLTAGE'].delete(0,END)
    entries['CURRENT'].delete(0,END)

    
def makeform(root, fields):
   entries = {}
   for field in fields:
      row = Frame(root)
      lab = Label(row, width=22, text=field+": ", anchor='w')
      ent = Entry(row)
      ent.insert(0,"0")
      row.pack(side=TOP, fill=X, padx=5, pady=5)
      lab.pack(side=LEFT)
      ent.pack(side=RIGHT, expand=YES, fill=X)
      entries[field] = ent
   return entries

if __name__ == '__main__':
   root = Tk()
   ents = makeform(root, fields)
   root.bind('<Return>', (lambda event, e=ents: fetch(e)))   
   b1 = Button(root, text=' CALCULATE ',
          command=(lambda e=ents: calculate(e)))
   b1.pack(side=LEFT, padx=5, pady=5)
   b2 = Button(root, text=' CLEAR ',
          command=(lambda e=ents: clear(e)))
   b2.pack(side=LEFT, padx=5, pady=5)
   b3 = Button(root, text='QUIT ', command=root.quit)
   b3.pack(side=LEFT, padx=5, pady=5)
   root.mainloop()
