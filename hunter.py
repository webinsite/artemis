#!/usr/bin/env python

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from models import Filename, Scan, Directory
from timeout import timeout, TimeoutError
import re
import os
import time
import hashlib
import json
import datetime
import config


FAKE_HASH = False
config = config.DevConfiguration()
engine = create_engine(config.SQLALCHEMY_DATABASE_URI)
DBSession = sessionmaker(bind=engine)
session = DBSession()




def get_directory_root(excludes, directory='/'):
    """Return a list of the directories root after removing
    excluded directories.

    Keywork arguments:
    directory -- the directory you wish to list (default '/')

    Notes:
    WARNING :: Have yet to test outside of using '/' as the directory,
    I assume this will not work with self.scan_filesystem().
    """
    return list(set(os.listdir(directory)) - set(excludes))


class DatabaseMixin:
    def __init__(self):
        self.engine = create_engine(config.SQLALCHEMY_DATABASE_URI)
        self.session = self.set_session()

    def set_session(self):
        DBSession = sessionmaker(bind=self.engine)
        session = DBSession()
        return session

    def get_session(self):
        return self.session

    def write_db(self, db_model, kwargs):
        """Try to add the directory path and hash to the Directory
        database.  Rollback if the hash already exists

        Keyword arguments:
        directory_path -- Full path of the directory_path

        Notes:
        """
        try:
            entry = db_model(
                created_at=datetime.datetime.now(),
                **kwargs
                )
            self.session.add(entry)
            self.session.commit()
            return entry
        except IntegrityError, e:
            self.session.rollback()
        return None


class FileDbEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, File):
            return {
                "hash": obj.hash,
                "last_seen": obj.last_seen
            }
        return json.JSONEncoder.default(self, obj)


class File:
    def __init__(self, path):
        self.ignore = self.compile_regex()
        self.path = path
        self.read = False
        self.last_seen = None

        self.analyze()

    def analyze(self):
        self.last_seen = time.time()
        try:
            self.hash = self.sha256()
            self.read = True
        except IOError:
            self.hash = None
            self.read = False
            pass

    def compile_regex(self):
        keywords = ['social security number','first name',
                'last name', 'middle initial', 'middle name',
                'phone number','date of birth','address','doctor','md','phd',
                'employment','employer','\d{3}-\d{2}-\d{4}','ssn']
        regex = ""
        compiled = "|".join(keywords)
        return compiled

    def has_phi(self, string):
        regex = re.compile(self.ignore)
        ssn = re.match(regex,string)
        if ssn:
            return True
        return False

    def get_acronym(self, keyword):
       return  "".join(item[0] for item in keyword.split())

    @timeout(15)
    def sha256(self):
        phi = False
        self.phi = None
        if FAKE_HASH:
            return ""
        h = hashlib.sha256(self.path)
        try:
            with open(self.path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    if self.has_phi(chunk.lower()):
                        phi = True
                    #    print self.path
                        #self.phi = {'keyword':self.keyword,'path':self.path,'string':chunk.lower()}
                        #print '#### Potential PHI Found #### : ', self.path

                    h.update(chunk)
                if phi:
                    pass
        except TimeoutError, e:
            return False
        return h.hexdigest()


class FileWalker:
    def __init__(self, path, ignored_dirs=[]):
        self.db = DatabaseMixin()
        self.session = self.db.get_session()
        self.root_path = path
        self.metrics = {}
        self.file_count = 0
        self.dir_count = 0
        self.dir_existed = 0
        self.dir_added = 0
        self.file_added = 0
        self.file_existed = 0
        self.ignored_dirs = ['/dev','/boot']

        self.start_time = 0
        self.end_time = 0

        self.file_map = {}
        self.problem_files = {}

    @property
    def scan_duration(self):
        if self.end_time == 0:
            return None
        return round(self.end_time - self.start_time, 2)

    @property
    def file_per_min(self):
        if self.end_time == 0 or self.file_count == 0:
            return None
        return round(self.file_count / ((self.end_time - self.start_time) / 60.0), 2)

    def write_directory_to_db(self, directory_path):
        data = self.db.write_db(Directory, directory_path)
        if data:
            self.dir_added += 1
        else:
            self.dir_existed += 1
        self.dir_count += 1
        return data

    def write_file_to_db(self, kwargs):
        data = self.db.write_db(Filename, kwargs)
        if data:
            self.file_added += 1
        else:
            self.file_existed += 1
        self.file_count += 1
        return data

    def write_scan_stats(self, kwargs):
        return self.db.write_db(Scan, kwargs)

    def is_ascii(self, string):
        """Breaks loop if any character isn't valid ascii.  Its a dirty
        hack but its quick and efficient

        Keyword arguments:
        string -- the string needed for validation
        """
        # An exploit to return false as soon as a non-ascii character is found
        return all(ord(character) < 128 for character in string)

    def scan(self, stop_after_n_directories=None):
        self.start_time = time.time()
        for dirName, subdirList, fileList in os.walk(self.root_path):
            if self.is_ascii(dirName):
                dir_id = self.write_directory_to_db({'directory_path':dirName})

            for f in fileList:
                p = os.path.join(dirName, f)
                if self.is_ascii(p):
                    file = File(p)
                    self.process_file(file, p)
                    self.write_file_to_db({'filename':f,'directory':dir_id,'hash':file.hash})
                    fileList.pop(fileList.index(f))

            if self.dir_count % 500 == 0:
                print("Processed %s files in %s directories" % (self.file_count, self.dir_count))

            if stop_after_n_directories and self.dir_count >= stop_after_n_directories:
                # break for debug
                break
        self.end_time = time.time()
        payload = {
                "dir_added":self.dir_added,
                "dir_existed":self.dir_existed,
                "dir_total":self.dir_count,
                "path":self.root_path,
                "file_added":self.file_added,
                "file_existed":self.file_existed,
                "file_total":self.file_count,
                "ended_epoch":self.end_time,
                "started_epoch":self.start_time
                }
        self.write_scan_stats(payload)


    def process_file(self, file, p):
        if not file.read:
            self.problem_files[p] = file
        else:
            self.file_map[p] = file




if __name__ == "__main__":
    excludes = ['boot','sys','proc','dev','run']
    dirs = get_directory_root(excludes=excludes)
    for d in dirs:
        fw = FileWalker('/'+d)
        fw.scan()
        print "Processed %s files in %s directories rooted at %s in %s sec, (%s f/min. Directories added: %s and %s existed already.)" % (fw.file_count, fw.dir_count, fw.root_path, fw.scan_duration, fw.file_per_min, fw.dir_added, fw.dir_existed)
