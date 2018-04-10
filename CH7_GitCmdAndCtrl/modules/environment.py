import os


def run(**kwargs):
    print("[*] In environment module.")
    return str(os.environ)