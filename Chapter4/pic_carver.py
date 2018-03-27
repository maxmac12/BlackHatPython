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


def get_http_headers(http_payload):
    """ Splits out the HTTP headers using regular expression from the given raw HTTP traffic"""
    try:
        # Split the headers off if it is HTTP traffic
        headers_raw = http_payload[:http_payload.index(b"\r\n\r\n") + 2]

        # Break out the headers
        headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers_raw.decode('ascii')))
    except:
        return None

    if "Content-Type" in headers:
        return headers
    else:
        return None


def extract_image(headers, http_payload):
    """ Determines if an image has been received in an HTTP response based on the given response header"""
    image      = None
    image_type = None

    try:
        if "image" in headers['Content-Type']:
            # Extract the image type from the MIME type.
            image_type = headers['Content-Type'].split("/")[1]

            # Extract the image body.
            image = http_payload[http_payload.index(b"\r\n\r\n") + 8:]

            # Decompress the image if compressed.
            try:
                if "Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        image = zlib.decompress(image, 16 + zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] == "deflate":
                        image = zlib.decompress(image)
            except Exception as inst:
                print(inst)
                pass
    except:
        return None, None

    return image, image_type


def http_assembler(pcap_file):
    carved_images  = 0
    faces_detected = 0
    img_data = []

    # Read in the PCAP file for processing
    a = scapy.rdpcap(pcap_file)

    # Separate each TCP session into a dictionary.
    sessions = a.sessions()

    for session in sessions:
        img_payload = b""
        img_type    = b""

        for packet in sessions[session]:
            # Capture HTTP responses for possible image extraction.
            if packet.haslayer(http.HTTP):
                pkt = packet.getlayer(http.HTTP)

                # Skip HTTP request packets
                if pkt.haslayer(http.HTTPRequest) or pkt.haslayer(http.HTTPResponse):
                    # Store any previous image data.
                    if img_type and img_payload:
                        img_data.append((img_type, img_payload))

                    # Check if the response contains image data.
                    header = dict(re.findall(b"(?P<name>.*?): (?P<value>.*?)\r\n", bytes(pkt)))
                    img_type = b""

                    if b"Content-Type" in header:
                        if b"image" in header[b"Content-Type"]:
                            # Get the new image type.
                            img_type = header[b'Content-Type'].split(b"/")[1]

                            # Reset the image data with the data contained in this response packet.
                            img_payload = bytes(pkt[scapy.Raw])
                elif img_type:
                    img_payload += bytes(pkt)
        if img_type and img_payload:
            img_data.append((img_type, img_payload))

    for type, data in img_data:
        # Store the image
        file_name = "{}-pic_carver_{}.{}".format(pcap_file, carved_images, type.decode())

        with open("{}/{}".format(pictures_dir, file_name), "wb") as fd:
            fd.write(data)
            print("Saved: {}".format(file_name))

            # Attempt face detection
            try:
                result = face_detect("{}/{}".format(pictures_dir, file_name), file_name)

                if result is True:
                    faces_detected += 1
            except Exception as inst:
                print(inst)
                pass

        carved_images += 1

    return carved_images, faces_detected


if __name__ == "__main__":
    carved_images, faces_detected = http_assembler(pcap_file)

    print("Extracted: {} images".format(carved_images))
    print("Detected: {} faces".format(faces_detected))
