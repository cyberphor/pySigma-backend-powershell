"""Downloads a dataset."""

from os import remove, rename
from requests import session
from zipfile import ZipFile

EXIT_SUCCESS = 0
DATASET = "dataset.zip"
URL = "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/archive/refs/heads/master.zip"


def main() -> int:
    """Downloads a dataset."""
    with session() as client:
        repo = client.get(URL)
        with open(DATASET, "wb") as download:
            download.write(repo.content)
        with ZipFile(DATASET, "r") as dataset:
            dataset.extractall(".")
        rename("EVTX-ATTACK-SAMPLES-master", "dataset")
    remove(DATASET)
    return EXIT_SUCCESS


if __name__ == "__main__":
    main()
