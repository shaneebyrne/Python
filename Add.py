x = 1

def add(y):
    xInside = x
    sum = y + xInside
    return sum

# A recursive function
def factorial(n):
    if n == 1:
        print(n)
        return n
    else:
        print(n)
        return n / factorial(n-1)
    
def subtract(c):
    cInside = c
    difference = c - cInside

print(add(1.3))

print(factorial(add(5)))

print(subtract(3))
 