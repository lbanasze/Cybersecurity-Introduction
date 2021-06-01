import hashlib
import numpy as np
import os
import random
import sqlite3

from flask import Flask, render_template, request, url_for, flash, redirect
app = Flask(__name__, static_folder='instance/static')

# Global variables
MAX_ATTEMPTS = 3
SPECIAL_CHAR = "!@#$%^&*"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 25

attempts = 0
current_user = "Guest"
display_errors = ""


# Setters and Getters
def set_current_user(user):
    global current_user
    current_user = user


def get_current_user():
    global current_user
    return current_user


def set_error_display(errors):
    global display_errors
    display_errors = errors


def get_error_display():
    global display_errors
    return display_errors


# This function sets up the user database
def create_database():
    try:
        conn = sqlite3.connect('tblUsers.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE tblUsers
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


# Ran once
def default_users():
    data = ["adminUser", "adminPassword123!", "admin"]
    data2 = ["modUser", "modPassword123!", "moderator"]
    data3 = ["premUser", "premPassword123!", "pUser"]
    data4 = ["testUser5", "testPassword123", "user"]

    try:
        conn = sqlite3.connect('tblUsers.db')
        c = conn.cursor()
        c.executemany("INSERT INTO tblUsers VALUES (?, ?, ?)", data)
        conn.commit()
        c.executemany("INSERT INTO tblUsers VALUES (?, ?, ?)", data2)
        conn.commit()
        c.executemany("INSERT INTO tblUsers VALUES (?, ?, ?)", data3)
        conn.commit()
        c.executemany("INSERT INTO tblUsers VALUES (?, ?, ?)", data4)
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


# This function sets up the comment database
def comment_database():
    try:
        conn = sqlite3.connect('tblComments.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE tblComments
                      (
                      username text,
                      comment text, 
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


# This function sets up the post database
def post_database():
    try:
        conn = sqlite3.connect('tblPosts.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE tblPosts
                      (
                      username text,
                      post text, 
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


# This function requires a username and password and logs in a user
def login_user(username, password):
    global attempts
    if not alphanumeric(username):
        return [False, "Username contains characters that are not allowed."]

    try:
        conn = sqlite3.connect('tblUsers.db')
        c = conn.cursor()

        # Check if user exists
        try:
            command = "SELECT COUNT(1) FROM tblUsers WHERE username= \"" + username + "\""
            c.execute(command)
            exists = c.fetchone()[0]

            if exists == 0:
                return[False, "User does not exist."]

        except sqlite3.DatabaseError:
            return [False, "Sorry, we can't seem to log you in right now. Please check back later."]

        # Validate password
        try:
            command = "SELECT password_hash FROM tblUsers WHERE username= \"" + username + "\""
            c.execute(command)
            password_hash = c.fetchone()[0]

            if (not authenticate(password_hash, password)) and attempts < MAX_ATTEMPTS:
                attempts += 1
                return [False, "Incorrect password."]

            elif attempts == MAX_ATTEMPTS:
                return [False, "Too many login attempts."]

        except sqlite3.DatabaseError:
            return [False, "Sorry, we can't seem to log you in right now. Please check back later."]

        # If the program has reached this point, the user has successfully logged in
        return [True, "Welcome, " + username]

    except sqlite3.DatabaseError:
        return [False, "Sorry, we can't seem to access our database right now. Please check back later."]

    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


# This function hashes a string
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
    while password_remaining > 0:
        rand = random.randint(1, password_remaining)
        if rand <= lengths[0]:
            r = 1
        elif rand <= (lengths[0] + lengths[1]):
            r = 2
        elif rand <= (lengths[0] + lengths[1] + lengths[2]):
            r = 3
        else:
            r = 4

        if r == 1:
            password += special_chars_in_pw[0]
            special_chars_in_pw = special_chars_in_pw[1:]
            lengths[0] -= 1
        elif r == 2:
            password += numbers_in_pw[0]
            numbers_in_pw = numbers_in_pw[1:]
            lengths[1] -= 1
        elif r == 3:
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


def create_user(user, password):
    # Check that the username is allowed
    if not alphanumeric(user):
        return [False, "Username contains characters that are not permitted."]
    # Check if user already exists
    try:
        conn = sqlite3.connect('tblUsers.db')
        c = conn.cursor()
        command = "SELECT COUNT(1) FROM tblUsers WHERE username= \"" + user + "\""
        c.execute(command)
        exists = c.fetchone()[0]

        if exists != 0:
            i = 1
            while exists != 0:
                user_suggestion = user + str(i)
                command = "SELECT COUNT(1) FROM tblUsers WHERE username= \"" + user_suggestion + "\""
                c.execute(command)
                exists = c.fetchone()[0]
                i += 1

            return [False, "Username already exists. Recommended username: " + user_suggestion]

    except sqlite3.IntegrityError:
        print("Sorry, we cannot process this request right now.")

    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()

    # Test password strength
    [password_good, error_message] = password_strength(password)
    if not password_good:
        return[False, error_message]

    # If password is good
    else:
        password = hash_pw(password)
        data = [(user, password, "user")]

        try:
            conn = sqlite3.connect('tblUsers.db')
            c = conn.cursor()
            c.executemany("INSERT INTO tblUsers VALUES (?, ?, ?)", data)
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


def insert_comment(user, com):
    data = [user, com]
    try:
        conn = sqlite3.connect('tblComments.db')
        c = conn.cursor()
        c.executemany("INSERT INTO tblComments VALUES (?, ?)", data)
        conn.commit()

    except sqlite3.IntegrityError:
        return [False, "This was already commented."]
    else:
        return [True, "Success!"]
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


def insert_post(user, text):
    data = [user, text]
    try:
        conn = sqlite3.connect('tblPosts.db')
        c = conn.cursor()
        c.executemany("INSERT INTO tblPosts VALUES (?, ?)", data)
        conn.commit()

    except sqlite3.IntegrityError:
        return [False, "Error. This post already exists."]
    else:
        return [True, "Success!"]
    finally:
        if c is not None:
            c.close()
        if conn is not None:
            conn.close()


def user_permission(username):

    try:
        conn = sqlite3.connect('tblUsers.db')
        c = conn.cursor()

        # Check if user exists
        try:
            command = "SELECT permission_level FROM tblUsers WHERE username= \"" + username + "\""
            c.execute(command)
            permission = c.fetchone()[0]
            return [True, permission]

        except sqlite3.DatabaseError:
            return [False, "Sorry, user does not exist."]

    except sqlite3.DatabaseError:
        return [False, "Sorry, we can't seem to check that right now. Please check back later."]


def sanitize_string(word):
    sanitized_string = ''
    for i in word:
        if i == '"':
            outchar = ''
        elif i == '%':
            outchar = ''
        else:
            outchar = i

        sanitized_string += outchar

    return sanitized_string


def alphanumeric(word):
    for i in word:
        upper = i in UPPERCASE
        lower = i in LOWERCASE
        num = i in "0123456789"
        if not upper and not lower and not num:
            return False

    return True


@app.route('/', methods=['GET', 'POST'])
def home():
    create_database()
    comment_database()
    post_database()
    rand_pw = random_password(25)
    return render_template('index.html',
                           pw=rand_pw,
                           err=get_error_display())


@app.route('/forum', methods=['GET', 'POST'])
def forum():
    return render_template('forum.html',
                           user=get_current_user())


@app.route("/login", methods=['GET', 'POST'])
def login():
    global attempts
    if attempts == 3:
        render_template('locked.html')

    else:
        if request.method == 'POST':
            button_value = request.form['Submit']

            success = False
            username = get_current_user()
            if button_value == 'Sign In':
                username = request.form.get('userE')
                password = request.form.get('passE')
                [success, error_message] = login_user(username, password)
                set_error_display(error_message)

            elif button_value == 'Create User':
                username = request.form.get('userN')
                password = request.form.get('passN')
                [success, error_message] = create_user(username, password)
                set_error_display(error_message)

            if success:
                set_current_user(username)
                return redirect(url_for('forum'))

            else:
                return redirect(url_for('home',
                                        err=get_error_display()))

        return render_template('index.html')


@app.route("/logout", methods=['GET', 'POST'])
def logout():
    set_current_user("Guest")
    return render_template('logout.html')


@app.route("/admin", methods=['GET', 'POST'])
def admin():
    [data_is_good, permission] = user_permission(get_current_user())
    if data_is_good:
        if permission == "admin":
            return render_template('admin.html')
        else:
            return render_template('oops.html')

    else:
        return redirect(url_for('forum'))


@app.route("/moderator", methods=['GET', 'POST'])
def moderator():
    [data_is_good, permission] = user_permission(get_current_user())
    if data_is_good:
        if permission == "moderator" or permission == "admin":
            return render_template('moderator.html')
        else:
            return render_template('oops.html')

    else:
        return redirect(url_for('forum'))


@app.route("/comment", methods=['GET', 'POST'])
def comment():
    [data_is_good, permission] = user_permission(get_current_user())
    if data_is_good:
        if permission == "moderator" or permission == "admin" or permission == "pUser" or permission == "user":
            comment_string = request.form.get('comment')
            if alphanumeric(comment_string):
                return render_template('comment.html')
            else:
                return render_template('oops.html')
        else:
            return redirect(url_for('oops.html'))

    else:
        return redirect(url_for('forum'))


@app.route("/post", methods=['GET', 'POST'])
def post():
    [data_is_good, permission] = user_permission(get_current_user())
    if data_is_good:
        if permission == "moderator" or permission == "admin" or permission == "pUser":
            post_string = request.form.get('post')
            if alphanumeric(post_string):
                return render_template('comment.html')
            else:
                return render_template('oops.html')
        else:
            return render_template('oops.html')

    else:
        return redirect(url_for('forum'))

