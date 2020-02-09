#!/usr/bin/env python3

import yaml
import sys
import logging


path = 'config/config.yaml'
if len(sys.argv) == 2:
    path = sys.argv[1]
try:
    with open(path, 'r') as stream:
        conf = yaml.load(stream, Loader=yaml.FullLoader)
except IOError:
    print('\nWARNING:\n'
          'before of running this bot you should create a file named `config.yaml` in `config`'
          '.\n\nOpen `config/config.example.yaml`'
          '\ncopy all'
          '\ncreate a file named `config.yaml`'
          '\nPaste and replace sample variables with true data.'
          '\nIf the file is in another path, you can specify it as the first parameter.')
    sys.exit()


BOT_TOKEN = conf['bot_token']
ADMINS = conf['admins_id']
#ADMINS_CHANNEL = conf['admins_channel']
ERROR_LOG = conf['error_log']

SQL_SERVER = conf['sql_server']
SQL_USER = conf['sql_user']
SQL_PASSWORD = conf['sql_password']
SQL_DATABASE = conf['sql_database']
SQL_FORMAT = conf['sql_table_format']
SQL_MAX_ROWS = int(conf['sql_max_rows'])

SQL_USER_TABLE_FORMAT = '%s%s_' % (SQL_FORMAT, 'user')
SQL_SECRET_KEY_TABLE_FORMAT = '%s%s_' % (SQL_FORMAT, 'secret_key')
SQL_CONFIG_TABLE_FORMAT = '%s%s_' % (SQL_FORMAT, 'config')
SQL_NONCE_TABLE_FORMAT = '%s%s_' % (SQL_FORMAT, 'nonce')
SQL_PUBLIC_KEY_TABLE_FORMAT = '%s%s_' % (SQL_FORMAT, 'public_key')
SQL_CIPHER_TEXT_TABLE_FORMAT = '%s%s_' % (SQL_FORMAT, 'cipher_text')

# READ_TIMEOUT default value is 6(int).
READ_TIMEOUT = conf['read_timeout']
# CONNECT_TIMEOUT default value is 9(int).
CONNECT_TIMEOUT = conf['connect_timeout']
# maintenance default value is False.
maintenance_mode = False

CALM_EXPRESSION = r'(●′ω`●)'
LAZY_EXPRESSION = r'٩(๑´0`๑)۶'
SURPRISED_EXPRESSION = r'(,,#ﾟДﾟ)'
NO_EXPRESSION = r'(＞﹏＜)'
GOOD_EXPRESSION = r'(๑•̀ㅂ•́)و✧'
SERVER_ERROR_EXPRESSION = r'SERVER ERROR! ٩(๑´0`๑)۶'
EXPIRE_ERROR_EXPRESSION = r'NO RESULT FOR EXPIRED MESSAGE! ٩(๑´0`๑)۶'
MAINTENANCE_EXPRESSION = r'Sorry, service is temporarily unavailable, we will recover as soon as possible. %s' % LAZY_EXPRESSION

# Default use the symmetirc encryption algorithm.
SYMMETRIC_ENCRYPTION_MODE = 0
ASYMMETRIC_ENCRYPTION_MODE = 1
# Default expire date is 12 hours: 60*60*6 = 21600.
DEFAULT_SYMMETRIC_EXPIRE_TIME = 21600
DEFAULT_ASYMMETRIC_EXPIRE_TIME = 21600
# NOT USE ANYMORE
# 24 hours: 60*60*24 = 86400.
# DEFAULT_NONCE_EXPIRE_DATE = 86400
# 31 days: 60*60*12*31 =
DEFAULT_MAX_EXPIRE_TIME = 1339200
# 10s
DEFAULT_MIN_EXPIRE_TIME = 10
# max decryption time.
# the max mysql int vaule.
DEFAULT_MAX_DECRYPTION_TIME = 1024
# the new register user's default max decryption time.
DEFAULT_DECRYPTION_TIME = 8

ENCRYPTION = 0
DECRYPTION = 1

# This is a global variable.
# {uid_hash1: False, uid_hash2: True}
keygen_confirm_dict = dict()

# {uid_hash1: 'second', uid_hash2: 'day'}
expire_date_unit_select_dict = dict()

# {uid_hash: 'private_key', ...}
private_key_dict = dict()
public_key_dict = dict()
nonce_dict = dict()
cipher_txt_dict = dict()
plain_text_dict = dict()

# command expire list
# [uid1_hash, uid2_hash, uid3_hash]
command_expire_list = list()
bot_start_time = 0
