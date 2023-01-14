import re

foo = re.compile(pattern = '\\w*\\s\\w*', flags = re.IGNORECASE)

if foo.match("event ID"):
  print("True")