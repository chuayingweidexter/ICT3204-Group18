import re

eventAttributeDictionary = {
    'Log Name': 2,
    'Source': 1,
    'Date': 1,
    'Event ID': 2,
    'Task': 1,
    'Level': 1,
    'Opcode': 1,
    'Keyword': 1,
    'User': 1,
    'User Name': 2,
    'Computer': 1

}


def getPyListFromTxt(eventListFileName, numEvents):
    eventList = []
    with open(eventListFileName) as file:
        eventCount = 0
        while eventCount < numEvents:
            line = file.readline().strip()
            eventsFound = re.findall("(Event\[)[0-9]+(\])", line)
            isBeginning = len(eventsFound) == 1  # if this line is the start of an event
            if (isBeginning):  # then parse it
                event = {}
                eventCount += 1
                eventNumberArray = re.findall("[0-9]+", line)
                eventNumber = int(eventNumberArray[0])
                event['Number'] = eventNumber
                for key, value in eventAttributeDictionary.items():  # this assumes it loops through the dict in the order the dict is initialized with
                    line = file.readline().strip()
                    wordArray = line.split()
                    event[key] = wordArray[value]

                line = file.readline()
                line = file.readline().strip()
                event['Description'] = line

                line = file.readline()
                line = file.readline()
                line = file.readline().strip().replace("Security ID:", "")
                event['Security ID'] = line
                line = file.readline().strip().replace("Account Name:", "")
                event['Account Name'] = line
                line = file.readline().strip().replace("Account Domain:", "")
                event['Account Domain'] = line
                line = file.readline()
                line = file.readline()
                line = file.readline()
                # print(event['Event ID'])
                if (int(event['Event ID']) == 4660):
                    # print('hi')
                    line = file.readline().strip().replace("Object Server:", "")
                    event['Object Server'] = line
                    file.readline()
                    file.readline()
                    file.readline()
                    file.readline()
                    line = file.readline().strip().replace("Process Name:", "")
                    event['Process Name'] = line
                    event['Object Name'] = "Null"
                    event['Operation Type'] = "Null"
                    event['Old Value'] = "Null"
                    event['New Value'] = "Null"
                elif (int(event['Event ID']) == 4657):
                    event['Object Server'] = "Null"
                    line = file.readline().strip().replace("Object Name:", "")
                    event['Object Name'] = line
                    file.readline()
                    file.readline()
                    line = file.readline().strip().replace("Operation Type:", "")
                    event['Operation Type'] = line
                    file.readline()
                    file.readline()
                    file.readline()
                    line = file.readline().strip().replace("Process Name:", "")
                    event['Process Name'] = line
                    file.readline()
                    file.readline()
                    file.readline()
                    line = file.readline().strip().replace("Old Value:", "")
                    event['Old Value'] = line
                    file.readline()
                    line = file.readline().strip().replace("New Value:", "")
                    event['New Value'] = line
                elif (int(event['Event ID']) == 4663):
                    line = file.readline().strip().replace("Object Server:", "")
                    event['Object Server'] = line
                    file.readline()
                    line = file.readline().strip().replace("Object Name:", "")
                    event['Object Name'] = line
                    file.readline()
                    file.readline()
                    file.readline()
                    file.readline()
                    file.readline()
                    line = file.readline().strip().replace("Process Name:", "")
                    event['Operation Type'] = "Null"
                    event['Process Name'] = line
                    event['Old Value'] = "Null"
                    event['New Value'] = "Null"
                    

                eventList.append(event)
    return eventList
