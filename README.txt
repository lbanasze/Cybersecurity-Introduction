Laura Banaszewski
CS 166 Lab 8

Welcome! For this project, I created the starts of a forum to post about dogs. However, it functions better as
a display for this class than an actual forum.

Setup:

For my project, you must have both flask and numpy installed. You can install using the following in terminal:
pip install numpy
pip install flask

Security Measures:
- To prevent SQL injection, I sanitize and check all data inserted into textboxes to make sure it is alphanumeric
before using it to check or insert into a database.
- To prevent cross site scripting, I contained the only javascript used within the html file itself.
- To protect users in the case of a data breach, all of passwords are hashed and salted before being inserted
into the database.
- The users are also protected by the password requirements.
- To prevent the possibility of a user attempting to navigate to the admin panels with the URL, I set every visitor
of the website to a Guest by default. The URL for all of the sensitive websites first checks if a user has the
proper permissions before the sensitive template is rendered.
- Log out option

Testing:

To test my project, simply run "werk.py" and open the website in a browser. You can test permissions using the following
accounts:

ADMIN:
adminUser
adminPassword123!

MODERATOR:
modUser
modPassword123!

PREMIUM USER:
premUser
premPassword123!

USER:
testUser5
TestPassword123!

GUEST:
Simply navigate to the forum.

The permissions for each of these accounts are listed under the forum once you log in, or navigate
manually using the URL.

For the sake of testing, I added buttons to view the admin and moderator control panels. This would likely
not exist on a real website, as the option to navigate to those parts of the site would only be available to those
with the right permissions.

Sources:
w3School used for Model code.