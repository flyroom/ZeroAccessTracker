# -*- coding:utf8 -*-
import os,os.path
class FileUtil:
        def __init__(self):
            kad_id=0
        @staticmethod
        def get_file_info_from_path(dir,topdown=True):
            dirinfo=[]
            for root, dirs, files in os.walk(dir, topdown):
                for name in files:
                    dirinfo.append(os.path.join(root,name))
            return dirinfo
        @staticmethod
        def get_dir_info_from_path(dir,topdown=True):
            fileinfo=[]
            for root, dirs, files in os.walk(dir, topdown):
                for name in dirs:
                    fileinfo.append(os.path.join(root,name))
            return fileinfo
        @staticmethod
        def get_file_info_from_path_time_sorted(path):
            mtime = lambda f: os.stat(os.path.join(path, f)).st_mtime
            return list(sorted(os.listdir(path), key=mtime))
        

