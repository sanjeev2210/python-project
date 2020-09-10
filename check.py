import numpy as np

#one-dimensional vertical inverse transforms
def horz_tx3(x):
    temp = np.zeros([4,4],dtype=np.int)
    for i in range(4):
        temp [0][i] = x[0][i] + x[2][i]
        temp [1][i] = x[0][i] - x[2][i]
        temp [2][i] = (x[1][i]>>1) - x[3][i]
        temp [3][i] = x[1][i] + (x[3][i]>>1)
    return temp

def horz_tx4(x):
    temp = np.zeros([4,4],dtype=np.int)
    for i in range(4):
        temp[0][i] = x[0][i] + x[3][i]
        temp[1][i] = x[1][i] + x[2][i]
        temp[2][i] = x[1][i] - x[2][i]
        temp[3][i] = x[0][i] - x[3][i]
    return temp

#one-dimensional horizontal inverse transforms
def horz_tx1(x):
    temp = np.zeros([4,4],dtype=np.int)
    for i in range(4):
        temp[i][0] = x[i][0] + x[i][2]
        temp[i][1] = x[i][0] - x[i][2]
        temp[i][2] = (x[i][1]>>1) - x[i][3]
        temp[i][3] = x[i][1] + (x[i][3]>>1)
    return temp

def horz_tx2(x):
    temp = np.zeros([4,4],dtype=np.int)
    for i in range(4):
        temp[i][0] = x[i][0] + x[i][3]
        temp[i][1] = x[i][1] + x[i][2]
        temp[i][2] = x[i][1] - x[i][2]
        temp[i][3] = x[i][0] - x[i][3]
    return temp

def my_func(a):
    if a < 0:
        return hex((a + 1) + 0xFFFF)
    return hex(a)


print("TestCases.............")
x1 = np.array([[0,20,0,0],[0,-25,0,0],[0,0,0,0],[0,0,0,0]],dtype=np.int)
x2 = np.array([[5,0,0,0],[0,0,10,0],[0,-15,0,0],[0,0,0,-20]],dtype=np.int)
x3 = np.array([[0,5,0,10],[-5,0,8,0],[0,7,9,0],[0,0,25,-15]],dtype=np.int)

vhex = np.vectorize(my_func)

print("Case--1")
h1 = horz_tx3(x1)
print((h1))
h2 = horz_tx4(h1)
print((h2))
v1 = horz_tx3(h2.T)
print((v1.T))
v2 = horz_tx4(v1)
print((v2.T))

print("Case--2")
h1 = horz_tx3(x2)
print((h1))
h2 = horz_tx4(h1)
print((h2))
v1 = horz_tx3(h2.T)
print((v1.T))
v2 = horz_tx4(v1)
print((v2.T))

print("Case--3")
h1 = horz_tx3(x3)
print((h1))
h2 = horz_tx4(h1)
print((h2))
v1 = horz_tx3(h2.T)
print((v1.T))
v2 = horz_tx4(v1)
print((v2.T))