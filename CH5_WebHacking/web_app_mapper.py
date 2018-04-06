import urllib.request
import queue
import threading
import os

threads = 10

# Define the target website and the local directory to download and extract the web application.
target = "http://www.blackhatpython.org"
directory = "C:/Users/Max/Downloads/Joomla_3.8.6-Stable-Full_Package"

# Defile list of file extensions to skip.
filters = [".jpg", ".gif", ".png", ".css"]

os.chdir(directory)

# Store for the files located on the remote server
web_paths = queue.Queue()

# Walk through all of the files and directories in the local web application directory.
for r, d, f in os.walk("."):
    for files in f:
        # Build the full path to the target files and test them against the filter list
        # to make sure we are only looking for the file types we want.
        remote_path = "{}/{}".format(r, files)

        if remote_path.startswith("."):
            remote_path = remote_path[1:]

        # Check if we found a file type we want.
        if os.path.splitext(files)[1] not in filters:
            web_paths.put(remote_path)


def test_remote():
    """
    Grabs a path from the web paths queue, add it to the target website's base path,
    and then attempt to retrieve it. If the file is successfully retrieved, the HTTP
    status code and full path to the file is outputted.
    """
    while not web_paths.empty():
        path = web_paths.get()
        url = "{}{}".format(target, path)

        request = urllib.request.Request(url)

        try:
            response = urllib.request.urlopen(request)
            content = response.read()

            print("[{}] => {}".format(response.status_code, path))
            response.close()
        except urllib.request.HTTPError as error:
            print("Failed {}".format(error.code))
        except urllib.request.URLError as error:
            print("Failed {}".format(error.reason))
        except Exception as error:
            print(error)


if __name__ == "__main__":
    # for i in range(threads):
    #     print("Spawning thread: {}".format(i))
    #     t = threading.Thread(target=test_remote)
    #     t.start()
    test_remote()
