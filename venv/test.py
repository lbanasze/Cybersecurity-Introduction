from flask import *
app = Flask(__name__)

import csv
import hashlib
import numpy as np
import os
import random
import sqlite3
# Global variables
MAX_ATTEMPTS = 3
SPECIAL_CHAR = "!@#$%^&*"
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 25

user = ""
attempts = 0

def createDatabase():
    try:
        conn = sqlite3.connect('tblAccounts.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE tblAccounts
                    (
                    username text,
                    password_hash text,
                    permission_level text
                    )''')
        conn.commit()
        return True
    except BaseException:
        return False
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()

def loginUser(user, password):
    global attempts
    try:
        conn = sqlite3.connect('tblAccounts.db')
        c = conn.cursor()

        # Check if user exists
        try:
            command = "SELECT COUNT(1) FROM tblAccounts WHERE username= \"" + user + "\""
            c.execute(command)
            exists = c.fetchone()[0]

            if (exists == 0):
                return[False, "User does not exist."]

        except sqlite3.DatabaseError:
            return [False, "Sorry, we can't seem to log you in right now. Please check back later."]

        # Validate password
        try:
            command = "SELECT password_hash FROM tblAccounts WHERE username= \"" + user + "\""
            c.execute(command)
            password_hash = c.fetchone()[0]

            command = "SELECT permission_level FROM tblAccounts WHERE username= \"" + user + "\""
            c.execute(command)
            permission = c.fetchone()[0]

            if (not authenticate(password_hash, password)) and attempts < MAX_ATTEMPTS:
                attempts += 1
                return [False, "Incorrect password."]

            elif (attempts == MAX_ATTEMPTS):
                reutrn [False, "Too many login attempts."]

        except sqlite3.DatabaseError:
            return [False, "Sorry, we can't seem to log you in right now. Please check back later."]

        # If the program has reached this point, the user has successfully logged in
        return [True, "Welcome, " + user]

    except sqlite3.DatabaseError:
        print("Sorry, we can't seem to access our database right now. Please check back later.")
        return False

    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


def hash_pw(plain_text, salt='') -> str:
    """
    :param plain_text: str (user-supplied password)
    :return: str (ASCII-encoded salt + hash)
    :param plain_text: str (user-supplied password)
    :param salt: str
    :return: str
    """

    salt = os.urandom(20).hex()
    hashable = salt + plain_text  # concatenate salt and plain_text
    hashable = hashable.encode('utf-8')  # convert to bytes
    this_hash = hashlib.sha1(hashable).hexdigest()  # hash w/ SHA-1 and hexdigest
    return salt + this_hash  # prepend hash and return


def authenticate(stored, plain_text, salt_length=None) -> bool:
    """
    Authenticate by comparing stored and new hashes.

    :param stored: str (salt + hash retrieved from database)
    :param plain_text: str (user-supplied password)
    :param salt_length: int
    :return: bool
    """
    salt_length = salt_length or 40  # set salt_length
    salt = stored[:salt_length]  # extract salt from stored value
    stored_hash = stored[salt_length:]  # extract hash from stored value
    hashable = salt + plain_text  # concatenate hash and plain text
    hashable = hashable.encode('utf-8')  # convert to bytes
    this_hash = hashlib.sha1(hashable).hexdigest()  # hash and digest
    return this_hash == stored_hash  # compare

def random_password(length):
    UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
    MIN_NUMBER = 1
    MAX_NUMBER = length

    # randomly generate the lengths for each piece of the password
    n = 4
    lengths = np.random.multinomial(length, np.ones(n) / n, size=1)[0]

    # generate the special characters
    special_chars_in_pw = ""
    for i in range(lengths[0]):
        rand = random.randint(0, len(SPECIAL_CHAR) - 1)
        special_chars_in_pw += SPECIAL_CHAR[rand]

    numbers_in_pw = ""
    for i in range(lengths[1]):
        rand = random.randint(0, 9)
        numbers_in_pw += str(rand)

    uppercase_in_pw = ""
    for i in range(lengths[2]):
        rand = random.randint(0, len(UPPERCASE) - 1)
        uppercase_in_pw += UPPERCASE[rand]

    lowercase_in_pw = ""
    for i in range(lengths[3]):
        rand = random.randint(0, len(LOWERCASE) - 1)
        lowercase_in_pw += LOWERCASE[rand]

    password_remaining = length
    password = ""
    while (password_remaining > 0):
        rand = random.randint(1, password_remaining)
        if (rand <= lengths[0]):
            r = 1
        elif (rand <= (lengths[0] + lengths[1])):
            r = 2
        elif (rand <= (lengths[0] + lengths[1] + lengths[2])):
            r = 3
        else:
            r = 4

        if (r == 1):
            password += special_chars_in_pw[0]
            special_chars_in_pw = special_chars_in_pw[1:]
            lengths[0] -= 1
        elif (r == 2):
            password += numbers_in_pw[0]
            numbers_in_pw = numbers_in_pw[1:]
            lengths[1] -= 1
        elif (r == 3):
            password += uppercase_in_pw[0]
            uppercase_in_pw = uppercase_in_pw[1:]
            lengths[2] -= 1
        else:
            password += lowercase_in_pw[0]
            lowercase_in_pw = lowercase_in_pw[1:]
            lengths[3] -= 1

        password_remaining -= 1

    return password

def password_strength(test_password) -> bool:
    """
    Check basic password strength. Return true if password
    meets minimum complexity criteria, false otherwise.

    :param test_password: str
    :return: bool
    """
    password_good = True
    return_message = ""
    if test_password.isalnum():
        return_message += "Password must contain at least one number.\n"
        password_good = False
    elif test_password.isalpha():
        return_message += "Password must contain at least one number.\n"
        password_good = False
    if len(test_password) < PASSWORD_MIN_LENGTH:
        return_message += "Password must be at least 8 characters.\n"
        password_good = False
    if len(test_password) > PASSWORD_MAX_LENGTH:
        return_message += "Password must be less than 25 characters.\n"
        password_good = False
    special_char_check = False
    has_upper = False
    has_lower = False
    has_digit = False
    for ch in test_password:
        if ch in SPECIAL_CHAR:
            special_char_check = True
        if ch.isupper():
            has_upper = True
        if ch.islower():
            has_lower = True
        if ch.isdigit():
            has_digit = True
    if not special_char_check:
        return_message += "Password must contain a special character.\n"
        password_good = False
    elif not has_upper:
        return_message += "Password must contain at least once uppercase character.\n"
        password_good = False
    elif not has_lower:
        return_message += "Password must contain at least one lowercase character.\n"
        password_good = False
    elif not has_digit:
        return_message += "Password must contain at least one digit.\n"
        password_good = False

    return[password_good, return_message]

def createUser(user, password):
    # Check if user already exists
    try:
        conn = sqlite3.connect('tblAccounts.db')
        c = conn.cursor()
        command = "SELECT COUNT(1) FROM tblAccounts WHERE username= \"" + user + "\""
        c.execute(command)
        exists = c.fetchone()[0]

        if (exists != 0):
            i = 1
            while(exists != 0):
                userSuggestion = user + str(i)
                command = "SELECT COUNT(1) FROM tblAccounts WHERE username= \"" + userSuggestion + "\""
                c.execute(command)
                exists = c.fetchone()[0]
                i += 1

            return [False, "Username already exists. Recommended username: " + userSuggestion]

    except sqlite3.IntegrityError:
        print("Sorry, we cannot process this request right now.")

    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()

    # Test password strength
    [password_good, error_message] = password_strength(password)
    if (not password_good):
        return[False, error_message]

    # If password is good
    else:
        password = hash_pw(password)
        data = [(user, password, "user")]

        try:
            conn = sqlite3.connect('tblAccounts.db')
            c = conn.cursor()
            c.executemany("INSERT INTO tblAccounts VALUES (?, ?, ?)", data)
            conn.commit()

        except sqlite3.IntegrityError:
            print("Error. This user already exists.")
        else:
            print("Success!")
        finally:
            if c is not None:
                c.close()
            if conn is not None:
                conn.close()

        return [True, "Welcome " + user]

@app.route('/', methods=['GET', 'POST'])
def home():
    createDatabase()
    return render_template('index.html')

@app.route('/forum', methods=['GET', 'POST' ])
def forum():
    return render_template('forum.html')

@app.route("/login", methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form.get('userE')
        password = request.form.get('passE')

        return redirect((url_for('forum')))

    return render_template('index.html')

@app.route("/new_user", methods=['GET', 'POST'])
def new_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        [success, messsage] = login(username, password)
        if(success):
            return redirect(url_for('forum'))
