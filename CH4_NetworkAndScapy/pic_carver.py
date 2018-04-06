import re
import zlib
import cv2

import scapy.all as scapy
from scapy.layers import http

pictures_dir = "pictures"
faces_dir    = "faces"
pcap_file    = "arper.pcap"


def face_detect(path, file_name):
    """ Detects faces and draws a green rectangle around faces in an image."""
    img = cv2.imread(path)

    if img is None:
        print("Cannot run face detection on {}".format(path))
        return False

    cascade = cv2.CascadeClassifier("haarcascade_frontalface_alt.xml")
    rects   = cascade.detectMultiScale(img, 1.3, 4, cv2.CASCADE_SCALE_IMAGE, (20, 20))

    if len(rects) == 0:
        return False

    rects[:, 2:] += rects[:, :2]

    # Highlight the faces in the image
    for x1, y1, x2, y2 in rects:
        cv2.rectangle(img, (x1, y1), (x2, y2), (127, 255, 0), 2)

    cv2.imwrite("{}/{}-{}".format(faces_dir, pcap_file, file_name), img)

    return True


def http_assembler(pcap_file):
    num_images = 0
    num_faces  = 0
    img_data   = []

    # Read in the PCAP file for processing
    a = scapy.rdpcap(pcap_file)

    # Separate each TCP session into a dictionary.
    sessions = a.sessions()

    for session in sessions:
        img_type     = b""
        img_encoding = b""
        img_payload  = b""

        for packet in sessions[session]:
            # Capture HTTP responses for possible image extraction.
            if packet.haslayer(http.HTTP):
                pkt = packet.getlayer(http.HTTP)

                if pkt.haslayer(http.HTTPRequest) or pkt.haslayer(http.HTTPResponse):

                    # Store any previous image data.
                    if img_type and img_payload:
                        img_data.append((img_type, img_encoding, img_payload))

                    # Reset the image type in preparation of new image data.
                    img_type = b""

                    # Extract the HTTP header to determine image details
                    header = dict(re.findall(b"(?P<name>.*?): (?P<value>.*?)\r\n", bytes(pkt)))

                    # Attempt to recover image type and compression details from the HTTP header.
                    if b"Content-Type" in header:
                        if b"image" in header[b"Content-Type"]:
                            # Extract the image type
                            img_type = header[b'Content-Type'].split(b"/")[1]

                            # Extract the image encoding
                            if b"Content-Encoding" in header:
                                img_encoding = header[b'Content-Encoding']
                            else:
                                img_encoding = b""

                            # Reset the image data with the data contained in this response packet.
                            img_payload = bytes(pkt[scapy.Raw])
                # Concatenate packets that contain additional image data.
                elif img_type:
                    img_payload += bytes(pkt)
        # Store any remaining image data from the current session.
        if img_type and img_payload:
            img_data.append((img_type, img_encoding, img_payload))

    for (img_type, img_encoding, img_payload) in img_data:

        # Decompress the image data if compressed.
        if img_encoding:
            try:
                if img_encoding == b"gzip":
                    img_payload = zlib.decompress(img_payload, 16 + zlib.MAX_WBITS)
                elif img_encoding == b"deflate":
                    img_payload = zlib.decompress(img_payload)
                else:
                    print("Unsupported image compression: {}".format(img_encoding.decode('utf-8')))
            except Exception as inst:
                print(inst)
                pass

        # Store the image
        file_name = "{}-pic_carver_{}.{}".format(pcap_file, num_images, img_type.decode('utf-8'))

        with open("{}/{}".format(pictures_dir, file_name), "wb") as fd:
            fd.write(img_payload)

            # Attempt face detection on image
            try:
                result = face_detect("{}/{}".format(pictures_dir, file_name), file_name)

                if result is True:
                    num_faces += 1
            except Exception as inst:
                print(inst)
                pass

            num_images += 1

    return num_images, num_faces


if __name__ == "__main__":
    num_images, num_faces = http_assembler(pcap_file)

    print("Extracted: {} images".format(num_images))
    print("Detected: {} faces".format(num_faces))
