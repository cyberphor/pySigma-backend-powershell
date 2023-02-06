import re

field = re.compile(pattern = "\\w+ +\\w+")

if field.match("field  name"):
  print("True")
else:
  print("False")