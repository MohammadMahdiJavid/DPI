'''
this file is used to configure settings for the DPI
'''

import os


def is_debugdir_exists():
    current_path = os.getcwd()
    debug_path = os.path.join(current_path, 'debug')
    return os.path.exists(debug_path)


DEBUG = is_debugdir_exists()
