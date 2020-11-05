# You work in the IT group of a department store and the latest analytics shows there is a bug that allows customers to
# go over their credit limit. The company's president has asked you to develop a new algorithm to solve this problem.
#
# Create your algorithm using pseudocode that determines if a department store customer has exceeded their credit limit.
# Be sure you gather the following inputs from the user:
#
# Account number
# Balance of the account
# Total cost of all the products the customer is looking to purchase
# Allowed credit limit
# After you gather the inputs, make sure your algorithm calculates if the user can purchase the products and provides a
# message to the user indicating if the purchase is approved or declined.

import random as ran

class BankAccount:
    accountNum = ran.getrandbits(20)

    def __init__(self,  balance):
         self.balance = balance

    def getAccountNum(self):
        return self.accountNum

    def getBalance(self):
        return self.balance

    def main(self):
        receipt = []
        one = Item("Hose", 12)
        two = Item("HDMI Cable", 22)
        three = Item("Television", 400)
        four = Item("Snickers Bar", 1.25)
        five = Item("Blu Ray Player", 200)
        receipt.append(one)
        receipt.append(two)
        receipt.append(three)
        receipt.append(four)
        receipt.append(five)
        print(receipt)
if __name__ == "main":
    main()

class Item:
    def __init__(self, discript, price):
        self.discript = discript
        self.price = price

    def getPrice(self):
        return self.price()

    def getDiscription(self):
        return self.discript

account = BankAccount(11000)

account.main()



