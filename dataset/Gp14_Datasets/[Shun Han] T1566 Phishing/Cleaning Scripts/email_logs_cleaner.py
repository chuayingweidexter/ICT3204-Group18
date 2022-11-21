import os
from email.message import Message
import requests
import json
import pandas as pd

# Change IP address of Mail server
ADDRESS = "http://192.168.91.5:8025/api/v2/messages"
# ADDRESS = "http://192.168.1.181:8025/api/v2/messages"
r = requests.get(f"{ADDRESS}?limit=250")
total = json.loads(r.text)["total"]

results = []

def filter_results(data):
    for row in data:
        content = row["Content"]
        mime = row["MIME"]
        if mime is None:
            mime = dict()
        results.append(content | mime)

if total > 250:
    for i in range((total // 250) + 1):
        with open (f'data{i}.json', 'w') as f:
            r = requests.get(f"{ADDRESS}?limit=250&start={i*250}")
            data = json.loads(r.text)["items"]
            filter_results(data)
            json.dump(data, f)
else:
    r = requests.get(f"{ADDRESS}?limit=250")
    data = json.loads(r.text)["items"]
    filter_results(data)
    with open('raw_logs.json', 'w') as f:
        f.write(f'{{"total":{total}, "count":{total}, "items":')
        json.dump(data, f)
        f.write("}")

files = [f for f in os.listdir('.') if os.path.isfile(f) if f.startswith('data')]
res = list()

for f1 in files:
    with open(f1, 'r') as infile:
        res.extend(json.load(infile))
    

    with open('raw_logs.json', 'w') as outfile:
            outfile.write(f'{{"total":{total}, "count":250, "items":')
            json.dump(res, outfile)
            outfile.write("}")
    os.remove(f1)



df = pd.DataFrame(results)

pd.options.display.max_columns = None
pd.options.display.max_colwidth = None
# ID, Date Created, Origin IP, Sender, Recipient, Subject, Body, File name, File type, File size, Email size
try:
    # ID
    df["Headers"] = df["Headers"].astype(str)
    df["Message-ID"] = df["Headers"].str.extract("('Message-ID':\s\['\S*\'])")
    df["Message-ID"] = df["Message-ID"].str.extract("(\['.+'\])")
    df["Message-ID"] = df["Message-ID"].str.replace(r"([\['\]])", '', regex=True)

    # Date Created
    df["Date"] = df["Headers"].str.extract("('Date':\s\['[\s,:\w\(\)-]*'\])")
    df["Date"] = df["Date"].str.extract("(\['.+'\])")
    df["Date"] = df["Date"].str.replace(r"([\['\]-])", '', regex=True)

    # Origin IP
    df["Origin IP"] = df["Headers"].str.extract("('Received':\s\['from\s\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\])")
    df["Origin IP"] = df["Origin IP"].str.extract("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

    # Sender
    df["Sender"] = df["Headers"].str.extract("('From': \['[\w@\.]*'\])")
    df["Sender"] = df["Sender"].str.extract("(\['[\w@\.]*'\])")
    df["Sender"] = df["Sender"].str.replace(r"[\[\]']", '', regex=True)

    # Recipient
    df["Recipient"] = df["Headers"].str.extract("('To': \['[\w@\.]*'\])")
    df["Recipient"] = df["Recipient"].str.extract("(\['[\w@\.]*'\])")
    df["Recipient"] = df["Recipient"].str.replace(r"[\[\]']", '', regex=True)

    # Subject
    df["Subject"] = df["Headers"].str.extract("('Subject': \['[\w\?\s=\-]*'\])")
    df["Subject"] = df["Subject"].str.extract("(\['[\w\?\s=\-]*'\])")
    df["Subject"] = df["Subject"].str.replace(r"[\[\]']", '', regex=True)

    # Email Body
    df["Email body"] = df["Body"]

    # File name
    df["Parts"] = df["Parts"].astype(str)
    df["Attachment"] = df["Parts"].str.extract("(\['attachment; filename=\"[\w\.]*\"'\])")
    df["Attachment"] = df["Attachment"].str.extract("(=\"[\w\.]*\")")
    df["Attachment"] = df["Attachment"].str.replace(r"([=\"]*)", '', regex=True)

    # File type
    df["File type"] = df["Parts"].str.extract("('Content-Type': \['[\w\/\-\.]*'\])")
    df["File type"] = df["File type"].str.extract("(\['[\w\/\-\.]*'\])")
    df["File type"] = df["File type"].str.replace(r"([\[\]'])", '', regex=True)

    # File size
    df["File size"] = df["Parts"].str.extract("('Size': \d+)")
    df["File size"] = df["File size"].str.extract("(\d+)")

    # Email size
    df["Email size"] = df["Size"]

    df = df[["Message-ID", "Date", "Origin IP", "Sender", "Recipient", "Subject", "Email body", "Attachment", "File type", "File size", "Email size"]]
    df.columns = ['ID', 'Date Created', 'Origin IP', 'Sender', 'Recipient', 'Subject', 'Email Body', 'File name', 'File type', 'File size', 'Email Size']

    df.to_csv("cleaned_email_logs.csv")


except KeyError:
    pass