import events
import txt_to_py_list
import json_dump
import json_to_csv
import os
import glob

eventListFileName = ["eventlog.txt","eventlog2.txt"]
jsonResultsFileName = "results.json"
csvFileName = "results.csv"

for event in eventListFileName:
    
    numEvents = events.getNumEvents(event)
    eventList = txt_to_py_list.getPyListFromTxt(event, numEvents)
    json_dump.dumpListAsJSON(eventList, jsonResultsFileName)
    json_to_csv.get_csv_from_JSON(jsonResultsFileName, event[:-4]+"_results.csv")


#read the path
file_path = os.getcwd()
#list all the files from the directory
csv_files = glob.glob('*.{}'.format('csv'))

fout=open("merged_Result.csv","a")
# now the rest:
counter =1

for file in csv_files:
    f = open(file)
    if counter != 1:
        innercounter = 1
        for line in f:
            if innercounter != 1:
                 fout.write(line)
            innercounter +=1
    else:
         for line in f:
             fout.write(line)
    f.close() # not really needed
    counter+=1
fout.close()
