# -*- coding: utf-8 -*-
"""
Created on Sun Oct 28 19:01:37 2018

@author: Seamus
"""
class Emf:
    
        def __init__(self, volt):
            self.volt = volt
    
        def getVoltage(self):
            return self.volt
   
        def setVoltage(self, volt):
            self.volt = volt
        
       


#v = Emf(45)

#print(v.getVoltage())

#v.setVoltage(11)

#print(v.getVoltage())