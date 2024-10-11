import hashlib

# creating a sample password database
passwdDB = {}

# Suppose user "hung" has password b"12345678"
hungPass = b"12345678"
salt = b"abcde"

# creating salted password
m = hashlib.sha256()
m.update(salt + hungPass)
saltedPass = m.digest()

# create entry for user "hung"
passwdDB["hung"] = (salt, saltedPass)
print("passwordDB = ", passwdDB)

# Now comes the implementation of the protocol

C_state = {}  # the internal state of C
S_state = {}  # the internal state of S
S_state["passwordDB"] = passwdDB


# Upon receiving (UserId, Password) from user
# C generates Message1 = UserId
def C_Generate_Message1(UserId, Password):
    # C needs to save the login information of the user
    global C_state
    C_state = {"UserId": UserId, "Password": Password}
    Message1 = UserId
    return Message1


# A sample Message1 m1
m1 = C_Generate_Message1("hung", b"12345678")
print("m1 = ", m1)


# Suppose C can send Message1 to S
# Upon receiving Message1 from C, S generates Message2 = (N, h, f, salt)
def S_Generate_Message2(Message1):
    UserId = Message1

    global S_state
    salt = S_state["passwordDB"][UserId][0]
    import random

    N = random.randint(1000, 2000)  # generate a random number N
    # select one-way functions h, f
    availableHashFunctions = ["sha256", "sha512", "md5"]
    f = random.choice(availableHashFunctions)
    h = "sha256"  # h must be the one-way function used in passwordDB
    Message2 = (N, h, f, salt)

    # retrieve hashing algorithms from the algorithm names
    if h == "sha256": h = hashlib.sha256()
    elif h == "sha512": h = hashlib.sha512()
    else: h = hashlib.md5()

    if f == "sha256": f = hashlib.sha256()
    elif f == "sha512": f = hashlib.sha512()
    else: f = hashlib.md5()

    # now let's update the state of S
    saltedPass = S_state["passwordDB"][UserId][1]
    f.update(bytes(N) + saltedPass)
    S_state = {"challenge": Message2, "expectedResponse": f.digest()}

    return Message2


# A sample Message2 m2
m2 = S_Generate_Message2(m1)
print("m2 = ", m2)


### Upon receiving Message2 from S, C generates Message3 = f(N, h(salt||P))
def C_Generate_Message3(Message2):
    N, h, f, salt = Message2

    # retrieve hashing algorithms
    if h == "sha256": h = hashlib.sha256()
    elif h == "sha512": h = hashlib.sha512()
    else: h = hashlib.md5()

    if f == "sha256": f = hashlib.sha256()
    elif f == "sha512": f = hashlib.sha512()
    else: f = hashlib.md5()

    # retrieve the user's password from the client's state
    global C_state
    P = C_state["Password"]

    # now perform the challenged task

    h.update(salt + P)
    saltedPass = h.digest()
    f.update(bytes(N) + saltedPass)
    Message3 = f.digest()
    return Message3


# A sample Message3 m3
m3 = C_Generate_Message3(m2)
print("m3 = ", m3)


## Upon receiving Message3 from C, S generates Message4 = True/False
def S_Generate_Message4(Message3):
    global S_state
    expected_response = S_state["expectedResponse"]

    # **to compare the received response with the expected response** (We edit here)
    if Message3 == expected_response:
        return True
    else:
        return False


# A sample Message4 m4
m4 = S_Generate_Message4(m3)
print("m4 = ", m4)

print("Replaying m3. Authentication result: ", S_Generate_Message4(m3))
