#Created on Sun Oct 28 18:32:18 2018

#@author: Seamus
#"""
#Ohm's law calculator
#"""

#"""
#This class contains functions which perform Ohm's law and power 
#law calculations based on variables from user input
#"""

from Intensity import Current
from Voltage import Emf
from Resistance import Impediance  
from Wattage import Power
import math


class Ohm:
    
        def __init__(self, choice):
            self.choice = choice
           
    
        #@staticmethod
        def calcVolt(self, i, r): 
            return i * r

        #@staticmethod
        def calcCurrent(self, r, v): 
            return r / v

        # @staticmethod
        def calcResistance(self, i, v): 
            return i / v

        #@staticmethod
        def power(self, v, i): 
            return v * i  

        #@staticmethod
        def pvolt(self, w, i): 
            return w / i

        #@staticmethod
        def pcurrent(self, w, v): 
            return w / v
                
        def calcWattageVA(self, v, a):
            return v * a
        
        def calcWattageAR(self, a, r):
            return pow(a,a)/r
        
        def calcWattageVR(self, v, r):
            return pow(v,v)/r
                
# First user interface menu. let's user choose between ohm's law and power law calculations.   
#print("Ohm's Law Calculations:\n 1. Voltage\n  2. Current \n 3. Resistance \n \n Power Law Calculations: \n 4. Wattage \n 5. Voltage \n 6. Current\n")
    


# Grab the user input
#select = int(raw_input(">>> "))

#x = Current(1)
#y = Emf(1)
#z = Impediance(1)

# Initialize our Ohm class
#Ohm = Ohm(select)

### Since we're asking for the current in multiple locations, simplify it
#if select in [1, 3, 4, 5]:
 #   i = float(raw_input("Enter current:"))
  #  x.setAmp(i)

### Again, since we're asking for voltage in multiple locations, simplify it
#if select in [2, 3, 4, 6]:
 #   v = float(raw_input("Enter voltage:"))
  #  y.setVoltage(v)

### Simplifying input for resistance
#if select in [1, 2]:
 #   r = float(raw_input("Enter resistance:"))
  #  z.setResistance(r)

## And lastly, simplifying for wattage
#if select in [5, 6]:
 #   w = float(raw_input("Enter wattage:"))

#output = None
#if select == 1:
 #   output = "{0} volts".format(Ohm.voltage(x.getAmp(), z.getResistance()))
#elif select == 2:
 #   output = "{0} amps".format(Ohm.current(z.getResistance(), y.getVoltage()))
#elif select == 3:  
 #   output = "{0} ohms".format(Ohm.resistance(x.getAmp(), y.getVoltage()))
#elif select == 4:
 #   output = "{0} watts".format(Ohm.power(x.getAmp(), y.getVoltage()))
#elif select == 5:
 #   output = "{0} volts".format(Ohm.pvolt(w, x.getAmp()))
#elif select == 6:
 #   output = "{0} amps".format(Ohm.pcurrent(w, y.getVoltage()))  

#if output is not None:
 #   print (output)
#else:
 #   print ("Invalid input values, please try again")

