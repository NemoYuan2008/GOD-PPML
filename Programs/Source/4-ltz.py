from Compiler.types import sint

nTimes = 8192

a = [i for i in range(nTimes)]
a_secret = sint(a)
res = a_secret < 0
