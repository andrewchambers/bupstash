#! /usr/bin/env python3

import string
import random
import os
import os.path as path
import sys

MIN_NAME_LEN = 1
MAX_NAME_LEN = 8
MIN_CHILD_DIRS = 0
MAX_CHILD_DIRS = 3
MIN_CHILD_FILES = 0
MAX_CHILD_FILES = 5
MIN_DEPTH = 0
MAX_DEPTH = 3
FILE_SIZES = [0, 1, 2, 3, 1024, 512*1024, 2*1024*1024, 8*1024*1024]

def random_file_name():
  name_len = random.randint(MIN_NAME_LEN, MAX_NAME_LEN)
  return ''.join(random.choices(string.ascii_lowercase, k=name_len))

def fresh_dir_ent(dir_path):
  while True:
    p = path.join(dir_path, random_file_name())
    if not path.exists(p):
      return p
  
def random_dir(dir_path="./random_dir", depth=None):

  if depth is None:
    depth = random.randint(MIN_DEPTH, MAX_DEPTH)

  os.mkdir(dir_path)

  num_files = random.randint(MIN_CHILD_FILES, MAX_CHILD_FILES)
  num_dirs = random.randint(MIN_CHILD_DIRS, MAX_CHILD_DIRS)

  if depth != 0:
    for i in range(num_dirs):
      random_dir(dir_path=fresh_dir_ent(dir_path), depth=depth-1)

  for i in range(num_files):
    with open(fresh_dir_ent(dir_path), "wb") as f:
      fsize = random.choice(FILE_SIZES)
      f.write(os.urandom(fsize))

if __name__ == '__main__':
  random_dir(sys.argv[1])