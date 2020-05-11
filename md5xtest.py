#!/usr/bin/python
from random import randint
import md5

rounds = 100000
a = md5.new("0").hexdigest()
for _ in range(rounds):
    a = md5.new(a).hexdigest()
    print(a)
print("done:", a)

