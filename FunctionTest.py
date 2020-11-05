#@author: Seamus

from random import randint
from HashTable import * 
import sys
from time import gmtime, strftime
import calendar
import time
ts = calendar.timegm(time.gmtime())
print(ts)
ts = time.time()
print(ts)

H=HashTable()
# H represents the function HashTable() from the HashTable class
H[54]="Cat"
H[26]="Dog"
H[93]="Lion"
H[17]="Tiger"
H[77]="Bird"
H[31]="Cow"
H[44]="Goat"
H[55]="Pig"
H[20]="Chicken"
H[22]="Ape"
H[48]="Human"
H[11]="Borg"

print(H.slots)
print(H.data)

print(H[20])

print(H[17])
H[20]='Duck'
print(H[20])
print(H[99])
print(H[54])
print(H[55])
 
r = True

while r: 
    x = randint(10,93)
    if x == 54:
        print("The", H[54], "is the word!")
        r = False
    elif x == 26:
        print("The", H[26], "is the word!")
        r = False
    elif x == 93:
        print("The", H[93], "is the word!")
        r = False
    elif x == 17:
        print("The", H[17], "is the word!")
        r = False
    elif x == 77:
        print("The", H[77], "is the word!")
        r = False    
    elif x == 31:
        print("The", H[31], "is the word!")
        r = False
    elif x == 44:
        print("The", H[44], "is the word!")
        r = False
    elif x == 55:
        print("The", H[55], "is the word!")
        r = False
    elif x == 20:
        print("The", H[20], "is the word!")
        r = False
    elif x == 22:
        print("The", H[22], "is the word!")
        r = False
    elif x == 48:
        print("The", H[48], "is the word!")
        r = False
    elif x == 11:
        print(H[11],"\"Resistance is Futile!\"")
    else:
        print(x)



