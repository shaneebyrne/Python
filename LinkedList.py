class Node:
    def __init__(self, dataval=None):
        self.dataval = dataval
        self.nextval = None

class LinkedList:
    def __init__(self):
        self.headval = None

# Print the linked list
    def listPrint(self):
        printval = self.headval
        while printval is not None:
            print (printval.dataval)
            printval = printval.nextval
            
    def atBegining(self,newdata):
        NewNode = Node(newdata)

# Update the new nodes next val to existing node
        NewNode.nextval = self.headval
        self.headval = NewNode

list = LinkedList()


list.headVal = Node("First")
sec = Node("Second")
trd = Node("Third")
fth = Node("fourth")

list.headVal.nextVal = sec 

sec.nextVal = trd 

trd.nextVal = fth 

list.listPrint()


list.atBegining("fifth")

#list.listPrint()

