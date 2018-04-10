"""
Basic extension of the Burp Suite's Burp Intruder.
"""

from burp import IBurpExtender # Required for Burp Suite Extensions
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator

import random


class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    """
    Extends the IBurpExtender and IIntruderPayloadGeneratorFactory classes of Burp Suite.
    """
    def registerExtenderCallbacks(self, callbacks):
        """
        Registers class with Burp Suite's Intruder tool to generate payloads.
        :param callbacks: Callback functions
        :return: None
        """
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()

        callbacks.registerIntruderPayloadGeneratorFactory(self)

        return

    def getGeneratorName(self):
        """
        Gets name of payload generator
        :return: Generator Name
        """
        return "Payload Generator"

    def createNewInstance(self, attack):
        """
        Creates new instance of fuzzer class.
        :param attack: Attack parameters
        :return: Instance of IIntruderPayloadGenerator class
        """
        return Fuzzer(self, attack)


class Fuzzer(IIntruderPayloadGenerator):
    """
    Custom Burp Suite Intruder payload generator class.
    """
    def __init__(self, extender, attack):
        """
        Extends the IIntruderPayloadGenerator class of Burp Suite.
        :param extender: Class to extend.
        :param attack: Attack parameters.
        """
        self._extender      = extender
        self._helpers       = extender._helpers
        self._attack        = attack
        self.max_payloads   = 10
        self.num_iterations = 0
        return

    def hasMorePayloads(self):
        """
        Checks if maximum iterations of fuzzer has been reached.
        :return: True if more fuzzer iterations exist, otherwise False.
        """
        if self.num_iterations == self.max_payloads:
            return False
        else:
            return True

    def getNextPayload(self, current_payload):
        """
        Receives an HTML payload and fuzzes it.
        :param current_payload: Original HTTP payload
        :return: Fuzzed HTTP payload
        """
        # Convert into a string
        payload = "".join(chr(x) for x in current_payload)

        # Call mutator to fuzz the POST
        payload = self.mutate_payload(payload)

        # Increase the number of fuzzing attempts
        self.num_iterations += 1

        return payload

    def reset(self):
        """
        Resets state of payload generator.
        :return: None
        """
        self.num_iterations = 0
        return

    def mutate_payload(self, original_payload):
        """
        Mutates a HTTP payload randomly from three mutators:
            - SQL injection test
            - XSS attempt
            - Randomly repeat chunks or original payload
        :param original_payload:  HTTP payload to mutate.
        :return: Mutated HTTP payload
        """
        # Pick a simple mutator or call an external script.
        picker = random.randint(1, 3)

        # Select a random offset in the payload to mutate.
        offset = random.randint(0, len(original_payload) - 1)
        payload = original_payload[:offset]

        # Random offset insert a SQL injection attempt.
        if picker == 1:
            payload += "'"

        # Jam an XSS attempt
        if picker == 2:
            payload += "<script>alert('FUZZ!);</script>"

        # Repeat a chunk of the original payload a random number of times.
        if picker == 3:
            chunk_length = random.randint(len(payload[offset:]), len(payload) - 1)
            repeater     = random.randint(1, 10)

            for i in range(repeater):
                payload += original_payload[offset:offset + chunk_length]

        # Add the remaining bits of the payload.
        payload += original_payload[offset:]

        return payload
