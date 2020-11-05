# You recently graduated college and you are applying for a programming job that requires the understanding of loops
# in Python. The manager you are interviewing with has asked you to take an assessment to prove your programming
# knowledge. Below are the requirements for the programming skills test.
# In Python, create a program that meets the following requirements:
# Take two integers from the user.
# Save the lower number as x.
# Save the largest integer as y.
# Write a loop that counts from x to y by twos.
# Print out the values of that loop using the Print function in Python.
# Write another loop that adds x and y, and saves the value as Z.
# Print out the values of Z using the Print function in Python.
# Provide the code and take a screenshot of the output, then paste the screenshot(s) into a Microsoft® Word document.

#Review Chapters 6 and 11 of Python for Everyone if you have additional questions on creating a program in Python.

#Submit your document.

class Loops:

   x = 0
   y = 0
   z = 0
   counter = " "

   def __init__(self,x,y):
       self.x = x
       self.y = y

   def add(self, x ):
       self.x = x

       while x <= self.y:
           #print("Value of X is: ", x, " Value of Y is: ", self.y)
           x = x + 2
           print("Value of X is: ", x, " Value of Y is: ", self.y)

       #return ("Value of X is: " , x, " Value of Y is: ", self.y)


   def isBigger(self, x, y):
       self.x = x
       self.y = y
       if self.x > y:
           self.y = x
       elif x > y:
           self.y = y
       else:
           print("Error")

   def getX(self):
        return self.x

   def getY(self):
       return self.y

   def addition(self,x,y):
       self.z = x + y

   def getZ(self):
       return self.z

def main(): # Main method
      example = Loops(1,3) #"Loops" object created!
      entry1 = input("Enter a Number to add:") #takes console input from the user and saves it as a String
      entry2 = input("Enter a number to add to the first:")
      print("type of number ", type(entry1)) #Identifies the data type of the input given, this being a String
      print("type of number ", type(entry2))
      example.x = int(entry1,2) # Converts console input saved as a String into an integer
      print(example.x, type(example.x))  #input converted integer is passed to the x variable of the class, confirmed by checking its data type.
      example.y = int(entry2,36)
      print(example.y, type(example.y))
      example.add(example.x)

if __name__ == '__main__':
    main()


#Diagnostic code, used for testing purposes

#attempt = Loops(2,500)
#attempt.main()
#trial = Loops(2,100)

#print(trial.add(1))
#trial.isBigger(1,1)
#print(trial.getX())
#print(trial.getY())
#trial.isBigger(2,1)
#print(trial.getX())
#print(trial.getY())
#trial.addition(3,5)
#print(trial.getZ())
