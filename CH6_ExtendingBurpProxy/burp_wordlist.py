"""
Extension of Burp Suite to generate a wordlist based on the output of Burp Spider.
"""

from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList

import re
from datetime import datetime
from HTMLParser import HTMLParser

# Define the maximum string length for a password within the wordlist.
max_pwd_length = 12


class TagStripper(HTMLParser):
    """
    Strips the HTML tags from HTTP responses.
    """
    def __init__(self):
        HTMLParser.__init__(self)
        self.page_text = []

    def handle_data(self, data):
        """
        Stores HTTP response page text.
        :param data: Text to store
        :return: None
        """
        self.page_text.append(data)

    def handle_comment(self, data):
        """
        Stores developer comments within an HTTP response page.
        :param data: Text to store
        :return: None
        """
        self.handle_data(data)

    def strip(self, html):
        """
        Feeds HTML code to HTMLParser and returns the page text.
        :param data: HTML code.
        :return: HTML page text.
        """
        self.feed(html)
        return " ".join(self.page_text)


class BurpExtender(IBurpExtender, IContextMenuFactory):
    """
    Extends the IBurpExtender and IContextMenuFactory classes of Burp Suite.
    """
    def registerExtenderCallbacks(self, callbacks):
        """
        Registers class with Burp Suite and provides a context menu to the user for requests in Burp.
        :param callbacks: Callback functions
        :return: None
        """
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self.context    = None
        self.hosts      = set()

        # Start with something common
        self.wordlist = set(["password"])

        # Setup extension
        callbacks.setExtensionName("Wordlist")
        callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self, context_menu):
        """
        Renders menu items that allows a context menu when a user right-clicks a request in Burp.
        :param context_menu: Application context to render menu.
        :return: Rendered menu items list.
        """
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem("Create Wordlist", actionPerformed=self.wordlist_menu))
        return menu_list

    def wordlist_menu(self, event):
        """
        Retrieves all of the host portions of the HTTP requests highlighted by the user and sends that
        information off for further processing.
        :param event: Trigger event for function.
        :return: None
        """
        # Grab the details of what the user clicked.
        http_traffic = self.context.getSelectedMessages()

        for traffic in http_traffic:
            http_service = traffic.getHttpService()
            host         = http_service.getHost()

            self.hosts.add(host)

            http_response = traffic.getResponse()

            if http_response:
                self.get_words(http_response)

        self.display_wordlist()
        return

    def get_words(self, http_response):
        """
        Adds words found within an HTTP response to the wordlist.
        :param http_response: HTTP response packet.
        :return: None
        """
        # Split HTTP response into its header and body.
        headers, body = http_response.tostring().split("\r\n\r\n", 1)

        # Skip non-text responses
        if headers.lower().find("content-type: text") == -1:
            return

        # Strip the HTML code from the rest of the page text.
        tag_stripper = TagStripper()
        page_text    = tag_stripper.strip(body)

        # Find all words starting with an alphabetic character followed by two ro more regex "word" characters.
        words = re.findall("[a-zA-Z]\w{2,}", page_text)

        # Add short words to our word list (long words most likely wouldn't be a password).
        for word in words:
            # Filter out long strings which probably wouldn't be a password.
            if len(word) <= max_pwd_length:
                self.wordlist.add(word.lower())

        return

    def mangle(self, word):
        """
        Alters a word into a number of password guesses based on common password creation "strategies".
        :param word: Base word to be altered.
        :return: List of altered versions of the base word.
        """
        # Create a list of suffixes to append to the end of the word.
        year = datetime.now().year
        suffixes = ["", "1", "!", year]
        mangled = []

        # Append suffixes to the base word and a capitalized version of the base word.
        for password in (word, word.capitalize()):
            for suffix in suffixes:
                mangled.append("{}{}".format(password, suffix))

        return mangled

    def display_wordlist(self):
        """
        Prints out the wordlist.
        :return: None.
        """
        print("#!comment: Wordlist for site(s) {}".format(", ".join(self.hosts)))

        for word in sorted(self.wordlist):
            for password in self.mangle(word):
                print(password)

        return
