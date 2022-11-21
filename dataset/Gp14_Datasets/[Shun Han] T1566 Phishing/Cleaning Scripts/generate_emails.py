# This script is used to generate "normal" email traffic on the mail server

import os
import sys
import smtplib
import datetime
import random
from datetime import timedelta
import email

from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
import mimetypes

from essential_generators import DocumentGenerator
from essential_generators import MarkovTextGenerator
from essential_generators import MarkovWordGenerator

gen = DocumentGenerator()
gen = DocumentGenerator(text_generator=MarkovTextGenerator(),
                        word_generator=MarkovWordGenerator())

DATE_FORMAT_1 = "%a, %d %b %Y %H:%M:%S -0700 (UTC)"

useSSL = False
address = "192.168.91.5"
# address = "192.168.1.181"
smtpPort = 1025


def makeHTMLMessage(subject, from_, to, date, dateFormat, body):
    msg = MIMEMultipart()
    if random.choice([True, False]):
        body += "\n" + gen.url()
    html = MIMEText(body, "html")

    msg["Subject"] = subject
    msg["From"] = from_
    msg["To"] = to
    msg["Date"] = date.strftime(dateFormat)

    msg.attach(html)
    return msg


def makeTextMessage(subject, from_, to, date, dateFormat, body, multipart=False):
    if multipart:
        msg = MIMEMultipart()
        msg.attach(MIMEText(body))
    else:
        msg = MIMEText(body)

    msg["Subject"] = subject
    msg["From"] = from_
    msg["To"] = to
    msg["Date"] = date.strftime(dateFormat)

    return msg


def makeMultipartMessage(subject, from_, to, date, dateFormat, textBody):
    msg = MIMEMultipart()
    htmlBody = gen.paragraph()
    html = MIMEText(htmlBody, "html")
    text = MIMEText(textBody)

    msg["Subject"] = subject
    msg["From"] = from_
    msg["To"] = to
    msg["Date"] = date.strftime(dateFormat)

    msg.attach(text)
    msg.attach(html)
    return msg


def addAttachment(subject, filename, sender, recepient, body="", base64Encode=True):
    msg = MIMEMultipart()

    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recepient
    msg["Date"] = datetime.datetime.now().strftime(DATE_FORMAT_1)

    msg.attach(MIMEText(body, "html"))

    contentType = mimetypes.guess_type(filename)[0]
    contentTypeSplit = contentType.split("/")

    part = MIMEBase(contentTypeSplit[0], contentTypeSplit[1])
    part.set_payload(open(filename, "rb").read())
    email.encoders.encode_base64(part)
    #part.add_header("Content-Type", contentType)
    part.add_header("Content-Disposition",
                    "attachment; filename=\"{0}\"".format(os.path.basename(filename)))

    msg.attach(part)
    return msg


def sendMail(msg):
    if not useSSL:
        server = smtplib.SMTP("{0}:{1}".format(address, smtpPort))
    else:
        server = smtplib.SMTP_SSL("{0}:{1}".format(address, smtpPort))

    fromAddress = msg["From"]
    to = [msg["To"]]

    try:
        server.sendmail(fromAddress, to, msg.as_string())
        server.quit()
    except UnicodeEncodeError as e:
        pass
#
# Seed the random generator
#


def main():
    random.seed(datetime.datetime.now().timestamp())

    choice = [makeTextMessage, makeHTMLMessage, makeMultipartMessage]

    try:
        if len(sys.argv) == 2 and sys.argv[1].isnumeric():
            for _ in range(int(sys.argv[1])):
                func = random.choice(choice)
                msg = func(
                    random.choice([gen.word(), gen.sentence()]),
                    gen.email(),
                    gen.email(),
                    datetime.datetime.now(),
                    DATE_FORMAT_1,
                    random.choice([gen.paragraph(), gen.sentence()])
                )
                sendMail(msg)
        elif len(sys.argv) == 2 and sys.argv[1].lower() == "-h":
            print("Usage:\npython generate_emails.py <int>: generate x number of email traffic\npython generate_emails.py <subject> <filename> <sender email> <recipient email> : sends an email with a file attachment to the recipient address with the sender's address")

        elif len(sys.argv) == 5:
            # subject, filename, sender, recepient
            new_msg = addAttachment(
                sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
            sendMail(new_msg)
        else:
            print("Usage:\npython generate_emails.py <int>: generate x number of email traffic\npython generate_emails.py <subject> <filename> <sender email> <recipient email> : sends an email with a file attachment to the recipient address with the sender's address")

    except Exception as e:
        print(
            f"An error occurred while trying to connect and send the email: {e}")
        print(sys.exc_info())


if __name__ == "__main__":
    main()
