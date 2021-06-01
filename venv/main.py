"""
Programming Assignment #1
Week 2
Laura Banaszewski
CS 166 / Fall 2020

This program reads usernames and passwords from a csv and uses them
to emulate a user logging in to a forum site. There is an admin, moderator,
user, and guest, all with different permissions.
"""

import csv
import hashlib
import numpy as np
import os
import random
import sqlite3
# Global variables
displayMenu = True
MAX_ATTEMPTS = 3
SPECIAL_CHAR = "!@#$%^&*"
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 25

def main():
    global displayMenu
    
    print("Welcome!")

    createDatabase()
    [user, permission] = login()

    while displayMenu:
        # Display the menu
        printMenu(user)

        # Get option input
        print("\nWhat would you like to do?")
        option = input()

        # Convert the input into an int
        integer = False
        while not integer:
            try:
                option = int(option)
                integer = True
            except:
                integer = False
                print("Invalid input. Please enter a valid option : ")
                option = input()

        # Check if the input is in range
        while option > 7 or option < 1:
            print("Invalid input. Please enter a valid option : ")
            option = input()


        # If the user is an admin, they can complete any action
        if (permission == "admin"):
            displayMenu = False

        # If the user is a moderator, they can complete options 3+
        elif (permission == "moderator"):
            if option == 1 or option == 2:
                print(
                    "You are not authorized to complete this action. Would you like to return to the main menu (y/n)?")
                menu = input()
                if menu == 'y' or menu == 'Y':
                    displayMenu = True
                else:
                    print("Goodbye!")
                    displayMenu = False
                    option = 6
            else:
                displayMenu = False

        # If the user is just a user, they can do options 4+
        elif (permission == "pUser"):
            if option == 1 or option == 2 or option == 3:
                print(
                    "You are not authorized to complete this action. Would you like to return to the main menu (y/n)?")
                menu = input()
                if menu == 'y' or menu == 'Y':
                    displayMenu = True
                else:
                    print("Goodbye!")
                    displayMenu = False
                    option = 6

            else:
                displayMenu = False

            # If the user is a guest, they can only do options 5 or 6
        elif (permission == "user"):
            if option != 5 and option != 6:
                print(
                    "You are not authorized to complete this action. Would you like to return to the main menu (y/n)")
                menu = input()
                if menu == 'y' or menu == 'Y':
                    displayMenu = True
                else:
                    print("Goodbye!")
                    displayMenu = False
                    option = 6

            else:
                displayMenu = False

        # Respond to option
        if option == 1:
            print("You have now accessed the user management control panel.")

        elif option == 2:
            print("You have now accessed the issue management control panel")

        elif option == 3:
            print("You have now accessed the post management control panel")

        elif option == 4:
            print("Make a post: ")

        elif option == 5:
            print("Welcome to the forum! You may view posts below.")

        else:
            displayMenu = False

    print("Exited.")

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

def login():
    try:
        attempts = 0
        conn = sqlite3.connect('tblAccounts.db')
        c = conn.cursor()
        print("Existing user? (y/n)")
        exist = input()
        global displayMenu
        while(exist != 'y' and exist != 'n'):
            print("Please enter a valid option. (y/n)")
            exist = input()

        permission = "user"
        if(exist == 'y'):
            print("Enter your username : ")
            user = input()

            # while user not in usernames:
                # print("That username is not in our system. Try again.\n")
                # print ("Enter your username : ")
                # user = input()

            print("Enter your password : ")
            password = input()

            try:
                conn = sqlite3.connect('tblAccounts.db')
                c = conn.cursor()

                for row in c.execute("SELECT * FROM tblAccounts"):
                    print(row)

                command = "SELECT password_hash FROM tblAccounts WHERE username= \"" + user + "\""

                c.execute(command)
                password_hash = c.fetchone()[0]

                command = "SELECT permission_level FROM tblAccounts WHERE username= \"" + user + "\""
                c.execute(command)
                permission = c.fetchone()[0]

                print(user, password_hash, permission)

                attempts = 1
                while (not authenticate(password_hash, password)) and attempts < MAX_ATTEMPTS:
                    attempts += 1
                    print("Incorrect password. Try again.")
                    password = input()

            except sqlite3.DatabaseError:
                print("This username does not exist.")
                displayMenu = False


        else:
            user = createUser()

        if (attempts == 3):
            print("Too many login attempts. Exiting...")
            displayMenu = False

        return [user, permission]

    except sqlite3.DatabaseError:
        print("Sorry, we can't seem to log you in right now. Please check back later.")
        displayMenu = False

    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()

    return["default", "user"]

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

    print(password)

def password_strength(test_password) -> bool:
    """
    Check basic password strength. Return true if password
    meets minimum complexity criteria, false otherwise.

    :param test_password: str
    :return: bool
    """
    if test_password.isalnum():
        print("Password must contain at least one number.")
        return False
    elif test_password.isalpha():
        print("Password must contain at least one number.")
        return False
    if len(test_password) < PASSWORD_MIN_LENGTH:
        print("Password must be at least 8 characters.")
        return False
    if len(test_password) > PASSWORD_MAX_LENGTH:
        print("Password must be less than 25 characters.")
        return False
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
        print("Password must contain a special character.")
        return False
    elif not has_upper:
        print("Password must contain at least once uppercase character.")
        return False
    elif not has_lower:
        print("Password must contain at least one lowercase character.")
        return False
    elif not has_digit:
        print("Password must contain at least one digit.")
        return False
    else:
        return True

def createUser():
    userCreated = True
    print("Choose a username: ")
    user = input()

    try:
        conn = sqlite3.connect('tblAccounts.db')
        c = conn.cursor()
        command = "SELECT COUNT(1) FROM tblAccounts WHERE username= \"" + user + "\""
        c.execute(command)
        exists = c.fetchone()[0]

        while(exists != 0):
            print("User already exists.Please choose a different username: ")
            user = input()
            command = "SELECT COUNT(1) FROM tblAccounts WHERE username= \"" + user + "\""
            c.execute(command)
            exists = c.fetchone()[0]

    except sqlite3.IntegrityError:
        print("Sorry, we cannot process this request right now.")
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


    print("Choose a password: ")
    password = input()
    while (not password_strength(password)):
        print("This password did not meet all of the requirements.")
        print("Enter a password: ")
        password = input()

    password = hash_pw(password)
    data = [(user, password, "user")]

    try:
        conn = sqlite3.connect('tblAccounts.db')
        c = conn.cursor()
        c.executemany("INSERT INTO tblAccounts VALUES (?, ?, ?)", data)
        conn.commit()

        for row in c.execute("SELECT * FROM tblAccounts"):
            print(row)

    except sqlite3.IntegrityError:
        print("Error. This user already exists.")
    else:
        print("Success!")
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


    # line = user + "," + password + ",user"

    # with open(filename, 'a') as file:
        # file.write(line)

    # openFile(filename)

    return user

def printMenu(user):
    print("Welcome " + user + "!")
    print("All options are listed below. You may also complete any action BELOW your rank.")
    print("If you're an admin, you may:")
    print("1. Manage users")
    print("2. Manage warnings")
    print("If you're a moderator, you may:")
    print("3. Manage posts")
    print("If you're a premium user, you may:")
    print("4. Make posts")
    print("If you're a user, you may:")
    print("5. View posts")
    print("6. Exit")

main()