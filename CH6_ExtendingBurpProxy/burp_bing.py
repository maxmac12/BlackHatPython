"""
Basic extension of Burp Suite to output detected URLs using Microsoft Bing's API.

Get a Bing API key here:
http://www.bing.com/dev/en-us/dev-center/
"""

from burp import IBurpExtender
from burp import IContextMenuFactory

from javax.swing import JMenuItem
from java.util import List, ArrayList
from java.net import URL

import socket
import urllib
import json
import re
import threading

bing_api_key      = "INSERT_KEY"
bing_api_host     = "api.cognitive.microsoft.com"
bing_api_urlquery = "https://api.cognitive.microsoft.com/bing/v7.0/search?count=20&q="


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

        # Set up extension
        callbacks.setExtensionName("Bing Extension")

        # Register menu handler.
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
        menu_list.add(JMenuItem("Send to Bing", actionPerformed=self.bing_menu))
        return menu_list

    def bing_menu(self, event):
        """
        Retrieves all of host portions of the HTTP requests highlighted by the user and sends that
        information off for further processing.
        :param event: Trigger event for function.
        :return: None
        """
        # Grab the details of what the user clicked.
        http_traffic = self.context.getSelectedMessages()

        print("{} request(s) Selected".format(len(http_traffic)))

        for traffic in http_traffic:
            http_service = traffic.getHttpService()
            host         = http_service.getHost()

            print("User selected host: {}".format(host))
            self.bing_search(host)

        return

    def bing_search(self, host):
        """
        Queries Microsoft Bing's service for all virtual hosts that have the same IP address as the given host.
        :param host: Host portion of a HTTP request.
        :return: None.
        """
        # Check if host is an IP address or hostname.
        is_ip = re.match("[0-9]+(?:\.[0-9]+){3}", host)

        if is_ip:
            # Host is an IP address.
            ip_address = host
            domain     = False
        else:
            # Host is a hostname. Resolve IP address of host.
            ip_address = socket.gethostbyname(host)
            domain     = True

        # Query Bing for all virtual hosts that have the same IP address of the given host.
        bing_query_string = "'ip:{}'".format(ip_address)
        t = threading.Thread(target=self.bing_query, args=(bing_query_string,))
        t.start()

        # Query Bing for any subdomains that have been indexed.
        if domain:
            bing_query_string = "'domain:{}'".format(host)

            # Start separate query threads so not to lock up Burp Suite.
            t = threading.Thread(target=self.bing_query, args=(bing_query_string,))
            t.start()

    def bing_query(self, bing_query_string):
        """
        Builds and sends an HTTP request containing the Bing query.
        :param bing_query_string: String to be queried
        :return: None
        """
        print("Performing Bing search: {}".format(bing_query_string))

        # Encode the query.
        quoted_query = urllib.quote(bing_query_string)

        # Build the HTTP request packet.
        http_request = "GET {}{} HTTP/1.1\r\n".format(bing_api_urlquery, quoted_query)
        http_request += "Host: {}\r\n".format(bing_api_host)
        http_request += "Connection: close\r\n"
        http_request += "Ocp-Apim-Subscription-Key: {}\r\n".format(bing_api_key)
        http_request += "User-Agent: BlackHat Python\r\n\r\n"

        # Make request to the Microsoft servers.
        json_body = self._callbacks.makeHttpRequest(bing_api_host, 443, True, http_request).tostring()

        # Split the headers from the HTTP response.
        json_body = json_body.split("\r\n\r\n", 1)[1]

        try:
            # Parse JSON response and output some information regarding the response.
            r = json.loads(json_body)

            if len(r["webPages"]["value"]):
                for site in r["webPages"]["value"]:
                    print("*" * 100)
                    print(site["name"])
                    print(site["url"])
                    print(site["snippet"])
                    print("*" * 100)

                    j_url = URL(site["url"])

            # Add discovered sites that were not in the target scope.
            if not self._callbacks.isInScope(j_url):
                print("Adding to Burp Scope")
                self._callbacks.includeInScope(j_url)
        except:
            print("No results from Bing")
            pass
