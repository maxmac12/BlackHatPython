import urllib.parse
import urllib.request
import urllib.error
import threading
import queue

threads    = 100
target_url = "http://testphp.vulnweb.com"

# From SVNDigger, https://www.netsparker.com/blog/web-security/svn-digger-better-lists-for-forced-browsing/
wordlist_file = "all.txt"
resume        = None
user_agent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
                "(KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"


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


def dir_bruter(word_queue, extensions=None):
    """
    Attempts to discover directories and files that are reachable on the target web server.

    :param word_queue: Queue populated with words to use for directories/files to test.
    :param extensions: Optional list of file extensions to test.
    :return:
    """
    while not word_queue.empty():
        attempt = word_queue.get()

        attempt_list = []

        # Check to see if there is a file extension; if not, it's a directory path we're bruting
        if "." not in attempt:
            attempt_list.append("/{}/".format(attempt))
        else:
            attempt_list.append("/{}".format(attempt))

        # If we want to bruteforce extensions
        if extensions:
            for extension in extensions:
                attempt_list.append("/{}{}".format(attempt, extension))

        # Iterate over our list of attempts
        for brute in attempt_list:
            url = "{}{}".format(target_url, urllib.parse.quote(brute))

            try:
                headers = {}
                headers["User-Agent"] = user_agent
                r = urllib.request.Request(url, headers=headers)

                response = urllib.request.urlopen(r)

                if len(response.read()):
                    print("[{}] => {}".format(response.code, url))
            except urllib.error.HTTPError as e:
                if hasattr(e, "code") and e.code != 404:
                    print("!!! {} => {}".format(e.code, url))
                pass
            except urllib.error.URLError as e:
                print("!!! {} => {}".format(e.reason, url))
                pass


if __name__ == "__main__":
    word_queue = build_wordlist(wordlist_file)
    extensions = [".php", ".bak", ".orig", ".inc"]

    for i in range(threads):
        t = threading.Thread(target=dir_bruter, args=(word_queue, extensions,))
        t.start()
