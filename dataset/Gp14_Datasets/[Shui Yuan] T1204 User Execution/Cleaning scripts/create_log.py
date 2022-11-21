import os
os.popen("wevtutil qe Application /f:text > \"%USERPROFILE%\Desktop\eventlog.txt\"") # this assumes you are on windows
os.popen("wevtutil qe OAlerts /f:text > \"%USERPROFILE%\Desktop\eventlog2.txt\"") # this assumes you are on windows

# Once you've produced the above file, just put it in the project folder (wherever you cloned it)
