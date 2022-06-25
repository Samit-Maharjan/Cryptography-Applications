"""
Generate MD5 checksum for all files placed under a folder
"""

import hashlib
import os

src_folder = "md5"


def generate_md5(fname, chunk_size=4096):
    """
    Function which takes a file name and returns md5 checksum of the file
    """
    hash = hashlib.md5()
    with open(fname, "rb") as f:
        # Read the 1st block of the file
        chunk = f.read(chunk_size)
        # Keep reading the file until the end and update hash
        while chunk:
            hash.update(chunk)
            chunk = f.read(chunk_size)

    # Return the hex checksum
    return hash.hexdigest()


if __name__ == "__main__":
    """
    Starting block of the script
    """

    md5_dict = dict()

    # Iterate through all files under source folder
    for path, dirs, files in os.walk(src_folder):
        for file_name in files:
            # print("Generating checksum for {}".format(file_name))
            md5_dict[file_name] = generate_md5(
                os.path.join(src_folder, file_name))

    with open(os.path.join(src_folder, "checksum.txt"), "w") as f:
        for key, value in md5_dict.items():
            f.write("{} : {}\n".format(value, key))
            print("{} : {}".format(value, key))

