#!/usr/bin/env python3
"""
Simple Calculator Application
Educational - No threats
"""

def add(a, b):
    """Add two numbers"""
    return a + b

def subtract(a, b):
    """Subtract two numbers"""
    return a - b

def multiply(a, b):
    """Multiply two numbers"""
    return a * b

def divide(a, b):
    """Divide two numbers"""
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b

class Calculator:
    """Basic calculator class"""
    def __init__(self):
        self.result = 0

    def calculate(self, a, op, b):
        """Perform calculation"""
        if op == '+':
            self.result = add(a, b)
        elif op == '-':
            self.result = subtract(a, b)
        elif op == '*':
            self.result = multiply(a, b)
        elif op == '/':
            self.result = divide(a, b)
        return self.result

if __name__ == "__main__":
    calc = Calculator()
    print("Calculator ready")
    print(f"5 + 3 = {calc.calculate(5, '+', 3)}")
    print(f"10 - 4 = {calc.calculate(10, '-', 4)}")
    print(f"6 * 7 = {calc.calculate(6, '*', 7)}")
    print(f"20 / 4 = {calc.calculate(20, '/', 4)}")
