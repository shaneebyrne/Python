# -*- coding: utf-8 -*-
"""
Created on Sun Oct 28 19:01:23 2018

@author: Seamus
"""

class Impediance:
    def __init__(self, ohm):
        self.ohm = ohm
    
    def getResistance(self):
        return self.ohm
    
    def setResistance(self, ohm):
        self.ohm = ohm


#x = Impediance(6)

#print(x.getResistance())

#x.setResistance(10)

#print(x.getResistance())
