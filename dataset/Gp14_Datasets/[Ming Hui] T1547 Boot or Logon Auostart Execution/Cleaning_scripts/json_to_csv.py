import csv
import json

eventHeaders = {
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
				'Computer': 1,
				'Description': 1,
                                'Security ID': 2,
                                'Account Name': 2,
                                'Account Domain': 2,
                                'Object Server': 2,
                                'Object Name': 2,
                                'Operation Type': 2,
                                'Process Name' : 2,
                                'Old Value': 2,
                                'New Value':2
}

def get_csv_from_JSON(jsonFileName, csvFileName):
	with open(jsonFileName) as json_file:
		eventsJSON = json.load(json_file)
		f = csv.writer(open(csvFileName, "w"), delimiter=',', lineterminator='\n',escapechar='\\')
		f.writerow([key for key, value in eventHeaders.items()])
		
		for event in eventsJSON:
			f.writerow([value for key, value in event.items()])

