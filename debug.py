import re

foo = re.compile(pattern = 'eventid', flags = re.IGNORECASE)

if foo.match("eventID"):
  print("True")