class Sum:

    def __init__(self, a, b):
        self.a = a
        self.b = b

    def add(self, a, b):
        c = a  + b
        return c

    def numbers(self, numberList):
        if len(numberList) == 1:
            return numberList[0]
        else:
            return numberList[0] + self.numbers(numberList[1:])



solution = Sum(1, 2)

print(solution.add(6,5))

list = [1,2,3,4,5,6,7,8,9,10]

print(solution.numbers(list))

