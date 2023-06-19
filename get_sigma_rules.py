
from shutil import move
from urllib.request import urlretrieve
from glob import glob
from os import remove
from zipfile import ZipFile

def main():
  urlretrieve("https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip", "tmp.zip")
  with ZipFile("tmp.zip", 'r') as zf:
    zf.extractall("tmp")
  for rule_dir in glob("tmp/sigma-master/rule*"):
    move(rule_dir, "rules")
  remove("tmp")
  remove("tmp.zip")

if __name__ == "__main__":
  main()