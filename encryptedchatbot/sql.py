#!/usr/bin/env python3

import pymysql
import sys
import random
import time

from encryptedchatbot import config

from telegram import ParseMode


def _sql_connect():
    '''Connect to the database.

    Returns:
        success: db.
        failed: exit the program.
    '''
    try:
        db = pymysql.connect(config.SQL_SERVER, config.SQL_USER,
                             config.SQL_PASSWORD, config.SQL_DATABASE)
    except Exception as e:
        print('can\'t connected to mysql server...\n%s' % str(e.args))
        sys.exit(1)

    return db


def _sql_commit(db):
    db.commit()


def _sql_rollback(db):
    db.rollback()


def _sql_close(db):
    db.close()


def _sql_insert_check(process_dict):
    '''Check if process_dict meets operating conditions.

    Args:
        A dict like this:
        {
            'uid_hash', ...(64B string),
            'public_key': ...(64B string),
            'create_time': ...(int),
        }

    Returns:
        0(int): pass.
        -1(int): not pass.
    '''

    if process_dict.__contains__('uid_hash'):
        if not isinstance(process_dict['uid_hash'], str):
            return -1
    else:
        return -1

    if process_dict.__contains__('public_key'):
        if not isinstance(process_dict['public_key'], str):
            return -1
    else:
        return -1

    if process_dict.__contains__('create_time'):
        if not isinstance(process_dict['create_time'], int):
            return -1
    else:
        return -1

    return 0


def _sql_table_exist(table_name):
    '''Check the table that if it existed.

    Returns:
        1: existed.
        0: not existed.
    '''
    db = _sql_connect()
    cursor = db.cursor()
    affected_rows = cursor.execute("SELECT * FROM information_schema.tables WHERE table_schema='%s' AND table_name='%s'" %
                                   (config.SQL_DATABASE, table_name))
    _sql_close(db)
    if affected_rows != 0:
        # the table existed
        return 1
    else:
        return 0


def _sql_table_rows(table_name):
    '''Get the rows of the data in the current table.

    Returns:
        0: empty table.
        int value: the current table's rows.
    '''
    db = _sql_connect()
    cursor = db.cursor()

    affected_rows = cursor.execute("SELECT COUNT(*) FROM %s" % table_name)
    if affected_rows == 0:
        rows = 0
    else:
        result = cursor.fetchone()
        # (1404,), rows is int
        rows = result[0]

    _sql_close(db)
    return rows


def _sql_table_full(table_name):
    '''Check the table that is full or not full .
    If the table is full,
    we need to create a new table to avoid some performance bottlenecks.
    The table max rows is define in config.SQL_MAX_ROWS, default is 500,000.

    Returns:
        1: full.
        0: not full.
    '''
    if _sql_table_rows(table_name) >= config.SQL_MAX_ROWS:
        # It full now
        return 1
    else:
        return 0


def _sql_one_table_name(type):
    '''Return a table name which not full at all.

    Args:
        'user': get an e_user_x name.
        'public_key': get an e_public_key_x table name.
        'secret_key': get an e_key_x table name.
        'config': get an e_config_x table name.
        'cipher_text': get an e_cipher_text_x table name.

    Returns:
        A table name.
    '''

    x = 0
    if type == 'user':
        while True:
            table_name = '%s%d' % (config.SQL_USER_TABLE_FORMAT, x)
            if _sql_table_exist(table_name) == 1:
                # Table exist.
                if _sql_table_full(table_name) == 0:
                    # Table not full.
                    return table_name
                else:
                    x += 1
            else:
                # Table not exist, create it.
                _sql_create_user_table(table_name)

    elif type == 'public_key':
        while True:
            table_name = '%s%d' % (config.SQL_PUBLIC_KEY_TABLE_FORMAT, x)
            if _sql_table_exist(table_name) == 1:
                # Table exist.
                if _sql_table_full(table_name) == 0:
                    # Table not full.
                    return table_name
                else:
                    x += 1
            else:
                # Table not exist, create it.
                _sql_create_public_key_table(table_name)

    elif type == 'secret_key':
        while True:
            table_name = '%s%d' % (config.SQL_SECRET_KEY_TABLE_FORMAT, x)
            if _sql_table_exist(table_name) == 1:
                # Table exist.
                if _sql_table_full(table_name) == 0:
                    # Table not full.
                    return table_name
                else:
                    x += 1
            else:
                # Table not exist, create it.
                _sql_create_secret_key_table(table_name)

    elif type == 'config':
        while True:
            table_name = '%s%d' % (config.SQL_CONFIG_TABLE_FORMAT, x)
            if _sql_table_exist(table_name) == 1:
                # Table exist.
                if _sql_table_full(table_name) == 0:
                    # Table not full.
                    return table_name
                else:
                    x += 1
            else:
                # Table not exist, create it.
                _sql_create_config_table(table_name)

    elif type == 'nonce':
        while True:
            table_name = '%s%d' % (config.SQL_NONCE_TABLE_FORMAT, x)
            if _sql_table_exist(table_name) == 1:
                # Table exist.
                if _sql_table_full(table_name) == 0:
                    # Table not full.
                    return table_name
                else:
                    x += 1
            else:
                # Table not exist, create it.
                _sql_create_nonce_table(table_name)

    elif type == 'cipher_text':
        while True:
            table_name = '%s%d' % (config.SQL_CIPHER_TEXT_TABLE_FORMAT, x)
            if _sql_table_exist(table_name) == 1:
                # Table exist.
                if _sql_table_full(table_name) == 0:
                    # Table not full.
                    return table_name
                else:
                    x += 1
            else:
                # Table not exist, create it.
                _sql_create_cipher_text_table(table_name)


def _sql_all_table_name(type):
    '''Return all the table name which type indicate.

    Args:
        'user': get all the e_user_x name.
        'public_key': get all the e_public_key_x table name.
        'secret_key': get the all e_key_x table name.
        'config': get all the e_config_x table name.
        'nonce': get all the e_nonce_x table name.
        'cipher_text': get all the e_cipher_text_x table name.

    Returns:
        A table name list.
        For example:
        [
            'e_user_0',
            'e_user_1',
            'e_user_2'
        ]
    '''
    x = 0
    table_name_list = list()
    if type == 'user':
        while True:
            table_name = '%s%d' % (config.SQL_USER_TABLE_FORMAT, x)
            if _sql_table_exist(table_name) == 1:
                # Table exist.
                table_name_list.append(table_name)
                x += 1
            else:
                return table_name_list

    elif type == 'public_key':
        while True:
            table_name = '%s%d' % (config.SQL_PUBLIC_KEY_TABLE_FORMAT, x)
            if _sql_table_exist(table_name) == 1:
                # Table exist.
                table_name_list.append(table_name)
                x += 1
            else:
                return table_name_list

    elif type == 'secret_key':
        while True:
            table_name = '%s%d' % (config.SQL_SECRET_KEY_TABLE_FORMAT, x)
            if _sql_table_exist(table_name) == 1:
                # Table exist.
                table_name_list.append(table_name)
                x += 1
            else:
                return table_name_list

    elif type == 'config':
        while True:
            table_name = '%s%d' % (config.SQL_CONFIG_TABLE_FORMAT, x)
            if _sql_table_exist(table_name) == 1:
                # Table exist.
                table_name_list.append(table_name)
                x += 1
            else:
                return table_name_list

    elif type == 'nonce':
        while True:
            table_name = '%s%d' % (config.SQL_NONCE_TABLE_FORMAT, x)
            if _sql_table_exist(table_name) == 1:
                # Table exist.
                table_name_list.append(table_name)
                x += 1
            else:
                return table_name_list

    elif type == 'cipher_text':
        while True:
            table_name = '%s%d' % (config.SQL_CIPHER_TEXT_TABLE_FORMAT, x)
            if _sql_table_exist(table_name) == 1:
                # Table exist.
                table_name_list.append(table_name)
                x += 1
            else:
                return table_name_list


def _sql_check_uid(uid_hash):
    '''Find if the uid_hash exists in the database.
    If it exists, we will not insert this data again.

    Returns:
        -1: uid_hash duplicate.
        0: not exist.
        1: exist.
    '''
    status = 0
    db = _sql_connect()
    cursor = db.cursor()
    for t in _sql_all_table_name('user'):
        affected_rows = cursor.execute(
            "SELECT create_time FROM %s WHERE uid_hash='%s'" % (t, uid_hash))
        if affected_rows == 1:
            status = 1
        elif affected_rows > 1:
            return -1

    _sql_close(db)
    return status


def _sql_create_user_table(table_name):

    db = _sql_connect()
    cursor = db.cursor()
    try:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS %s (uid_hash CHAR(64) NOT NULL, create_time INT UNSIGNED NOT NULL)" % table_name)
    except Exception:
        _sql_rollback(db)
        _sql_close(db)
        return -1

    _sql_close(db)
    return 0


def _sql_create_public_key_table(table_name):

    db = _sql_connect()
    cursor = db.cursor()
    '''Why the length is 64?
    >>> nacl.secret.SecretBox.KEY_SIZE
    32(bytes)
    >>> len(sk._private_key)
    32(bytes)
    >>> len(sk.public_key._public_key)
    32(bytes)

    In memory.
    |  0   |  1   |  2   |  3   | ... (address)
    | 0x15 | 0x85 | ...  | ...  | ... (bytes)
    |  1   |  5   |  8   |  5   | ... (hex string)

    So, after convert the bytes => hex string, we need 64 bytes to store the data.
    '''
    try:
        # Remove the secret_key here.
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS %s (uid_hash CHAR(64) NOT NULL, public_key CHAR(64) NOT NULL, expire_time INT UNSIGNED NOT NULL)" % table_name)
    except Exception:
        _sql_rollback(db)
        _sql_close(db)
        return -1

    _sql_close(db)
    return 0


def _sql_create_secret_key_table(table_name):

    db = _sql_connect()
    cursor = db.cursor()

    try:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS %s (secret_key_hash CHAR(64) NOT NULL, secret_key CHAR(64) NOT NULL, expire_time INT UNSIGNED NOT NULL, remain_time INT NOT NULL)" % table_name)
    except Exception:
        _sql_rollback(db)
        _sql_close(db)
        return -1

    _sql_close(db)
    return 0


def _sql_create_config_table(table_name):
    '''
    excryption_mode == 0: symmetric encryption mode
    excryption_mode == 1: asymmetric encryption mode
    encrypt_decrypt == 0: need encryption operation.
    encrypt_decrypt == 1: need decryption operation.
    '''
    db = _sql_connect()
    cursor = db.cursor()
    try:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS %s (uid_hash CHAR(64) NOT NULL, sexpire_date INT UNSIGNED NOT NULL, aexpire_date INT UNSIGNED NOT NULL, encryption_mode INT NOT NULL, emoji_mode INT NOT NULL, remain_time INT NOT NULL)" % table_name)
    except Exception:
        _sql_rollback(db)
        _sql_close(db)
        return -1

    _sql_close(db)
    return 0


def _sql_create_nonce_table(table_name):

    db = _sql_connect()
    cursor = db.cursor()
    try:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS %s (nonce_hash CHAR(64) NOT NULL, nonce CHAR(64) NOT NULL, expire_time INT UNSIGNED NOT NULL)" % table_name)
    except Exception:
        _sql_rollback(db)
        _sql_close(db)
        return -1

    _sql_close(db)
    return 0


def _sql_create_cipher_text_table(table_name):

    db = _sql_connect()
    cursor = db.cursor()
    try:
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS %s (cipher_text_hash CHAR(64) NOT NULL, cipher_text TEXT NOT NULL, expire_time INT UNSIGNED NOT NULL, remain_time INT NOT NULL)" % table_name)
    except Exception:
        _sql_rollback(db)
        _sql_close(db)
        return -1

    _sql_close(db)
    return 0


def _sql_table_rows(table_name):
    '''Get the table rows.
    '''
    db = _sql_connect()
    cursor = db.cursor()
    affected_rows = cursor.execute("SELECT COUNT(*) FROM %s" % table_name)
    result = cursor.fetchone()
    if affected_rows == 0:
        rows = 0
    else:
        rows = result[0]
    return rows


def sql_register(process_dict):
    '''Process the date from dict while a user register.
    We need insert the uid_hash, create_time to the e_user_x table.
    And then, insert the uid_hash, secret_key, public_key to the e_key_x table (x is a number).

    Args:
        A dict like this:
        {
            'uid_hash', ...(64B str),
            'public_key': ...(64B str),
            'create_time': ...(int)
        }

    Returns:
        -1: insert failed.
        0: insert success.
        1: uid_hash existed in the table, not insert.
        2: uid_hash duplicate.
    '''

    if _sql_insert_check(process_dict) != 0:
        # print('_sql_insert_check failed')
        return -1

    uid_status = _sql_check_uid(process_dict['uid_hash'])
    if uid_status == 1:
        return 1
    elif uid_status == -1:
        # Hope this command nerver executed.
        return 2

    db = _sql_connect()
    cursor = db.cursor()

    try:
        user_table_name = _sql_one_table_name('user')
        affected_rows = cursor.execute("INSERT INTO %s (uid_hash, create_time) VALUES ('%s', '%d')" % (
            user_table_name, process_dict['uid_hash'], process_dict['create_time']))
        if affected_rows != 1:
            # print('user insert failed')
            return -1

        config_table_name = _sql_one_table_name('config')
        affected_rows = cursor.execute("INSERT INTO %s (uid_hash, sexpire_date, aexpire_date, encryption_mode, emoji_mode, remain_time) VALUES ('%s', '%d', '%d', '%d', '%d', '%d')" % (
            config_table_name, process_dict['uid_hash'], config.DEFAULT_SYMMETRIC_EXPIRE_TIME, config.DEFAULT_ASYMMETRIC_EXPIRE_TIME, 0, 0, config.DEFAULT_DECRYPTION_TIME))
        if affected_rows != 1:
            # print('config insert failed')
            return -1

        public_key_table_name = _sql_one_table_name('public_key')
        affected_rows = cursor.execute("INSERT INTO %s (uid_hash, public_key, expire_time) VALUES ('%s', '%s', '%s')" % (
            public_key_table_name, process_dict['uid_hash'], process_dict['public_key'], (process_dict['create_time'] + config.DEFAULT_ASYMMETRIC_EXPIRE_TIME)))
        if affected_rows != 1:
            # print('public_key insert failed')
            return -1

    except Exception:
        _sql_rollback(db)
        _sql_close(db)
        # print('sql execute error: %s' % str(e.args))
        return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_check_user(uid_hash):
    '''Check the user register status.

    Retruns:
        -1: duplicate.
        0: no register.
        1: registerd.
    '''

    return _sql_check_uid(uid_hash)


def sql_check_database():
    '''Do the check job.

    Returns:
        0: very good, do nothing.
        1: need create the init table;
    '''

    status = 0
    # We only check the *_0 table(init table) existed or not.
    user_table_name = '%s%d' % (config.SQL_USER_TABLE_FORMAT, 0)
    public_key_table_name = '%s%d' % (config.SQL_PUBLIC_KEY_TABLE_FORMAT, 0)
    secret_key_table_name = '%s%d' % (config.SQL_SECRET_KEY_TABLE_FORMAT, 0)
    config_table_name = '%s%d' % (config.SQL_CONFIG_TABLE_FORMAT, 0)
    nonce_table_name = '%s%d' % (config.SQL_NONCE_TABLE_FORMAT, 0)
    cipher_text_table_name = '%s%d' % (config.SQL_CIPHER_TEXT_TABLE_FORMAT, 0)

    if _sql_table_exist(user_table_name) == 0:
        _sql_create_user_table(user_table_name)
        status = 1

    if _sql_table_exist(public_key_table_name) == 0:
        _sql_create_public_key_table(public_key_table_name)
        status = 1

    if _sql_table_exist(secret_key_table_name) == 0:
        _sql_create_secret_key_table(secret_key_table_name)
        status = 1

    if _sql_table_exist(config_table_name) == 0:
        _sql_create_config_table(config_table_name)
        status = 1

    if _sql_table_exist(nonce_table_name) == 0:
        _sql_create_nonce_table(nonce_table_name)
        status = 1

    if _sql_table_exist(cipher_text_table_name) == 0:
        _sql_create_cipher_text_table(cipher_text_table_name)
        status = 1

    return status


def sql_check_secret_key_expired_job():
    '''Do the check job.

    Retruns:
        A secret_key hash list which contains secret_key_hash symmetric expired.
        For example:
        [
            secret_key_hash_1,
            secret_key_hash_2,
            secret_key_hash_3,
            ...
        ]
    '''

    now_time = int(time.time())
    db = _sql_connect()
    cursor = db.cursor()
    secret_key_hash_list = list()

    for t in _sql_all_table_name('secret_key'):
        affected_rows = cursor.execute(
            "SELECT secret_key_hash FROM %s WHERE expire_time<'%d'" % (t, now_time))
        if affected_rows != 0:
            fetch_tuple = cursor.fetchall()
            for ft in fetch_tuple:
                secret_key_hash_list.append(ft[0])

    _sql_close(db)
    if len(secret_key_hash_list) != 0:
        return secret_key_hash_list
    else:
        return None


def sql_check_public_key_expired_job():
    '''Do the check job.

    Retruns:
        A uid_list which contains uid_hash symmetric expired.
        For example:
        [
            uid_hash_1,
            uid_hash_2,
            uid_hash_3,
            ...
        ]
    '''

    now_time = int(time.time())
    db = _sql_connect()
    cursor = db.cursor()
    uid_hash_list = list()

    for t in _sql_all_table_name('public_key'):
        affected_rows = cursor.execute(
            "SELECT uid_hash FROM %s WHERE expire_time<'%d'" % (t, now_time))
        if affected_rows != 0:
            fetch_tuple = cursor.fetchall()
            for ft in fetch_tuple:
                uid_hash_list.append(ft[0])

    _sql_close(db)
    if len(uid_hash_list) != 0:
        return uid_hash_list
    else:
        return None


def sql_check_nonce_expired_job():
    '''Do the check job.

    Retruns:
        A nonce_hash_list which contains uid_hash symmetric expired.
        For example:
        [
            nonce_hash_1,
            nonce_hash_2,
            nonce_hash_3,
            ...
        ]
    '''

    now_time = int(time.time())
    db = _sql_connect()
    cursor = db.cursor()
    nonce_hash_list = list()

    for t in _sql_all_table_name('nonce'):
        affected_rows = cursor.execute(
            "SELECT nonce_hash FROM %s WHERE expire_time<'%d'" % (t, now_time))
        if affected_rows != 0:
            fetch_tuple = cursor.fetchall()
            for ft in fetch_tuple:
                nonce_hash_list.append(ft[0])

    _sql_close(db)
    if len(nonce_hash_list) != 0:
        return nonce_hash_list
    else:
        return None


def sql_check_cipher_text_expired_job():
    '''Do the check job.

    Retruns:
        A nonce_hash_list which contains uid_hash symmetric expired.
        For example:
        [
            cipher_text_hash_1,
            cipher_text_hash_2,
            cipher_text_hash_3,
            ...
        ]
    '''

    now_time = int(time.time())
    db = _sql_connect()
    cursor = db.cursor()
    cipher_text_hash_list = list()

    for t in _sql_all_table_name('cipher_text'):
        affected_rows = cursor.execute(
            "SELECT cipher_text_hash FROM %s WHERE expire_time<'%d'" % (t, now_time))
        if affected_rows != 0:
            fetch_tuple = cursor.fetchall()
            for ft in fetch_tuple:
                cipher_text_hash_list.append(ft[0])

    _sql_close(db)
    if len(cipher_text_hash_list) != 0:
        return cipher_text_hash_list
    else:
        return None


def sql_get_all_expire_date(uid_hash):
    '''Get the expire date by uid_hash.

    Args:
        uid_hash(int).

    Returns:
        success: dict.
        For example:
        {
            'sexpire_date': ...(int),
            'aexpire_date': ...(int)
        }
        failed: none.
    '''

    db = _sql_connect()
    cursor = db.cursor()
    for t in _sql_all_table_name('config'):
        affected_rows = cursor.execute(
            "SELECT sexpire_date, aexpire_date FROM %s WHERE uid_hash='%s' LIMIT 1" % (t, uid_hash))
        if affected_rows != 0:
            # ('xxxxxxxx',)
            expire_date_dict = dict()
            fetch_tuple = cursor.fetchone()
            expire_date_dict['sexpire_date'] = fetch_tuple[0]
            expire_date_dict['aexpire_date'] = fetch_tuple[1]
            _sql_close(db)
            return expire_date_dict

    _sql_close(db)
    return None


def sql_get_secret_key_expire_date_from_config(uid_hash):
    '''Get the symmetric expire date.
    '''
    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('config'):
        affected_rows = cursor.execute(
            "SELECT sexpire_date FROM %s WHERE uid_hash='%s' LIMIT 1" % (t, uid_hash))
        if affected_rows != 0:
            expire_time = cursor.fetchone()[0]
            _sql_close(db)
            return expire_time

    _sql_close(db)
    return None


def sql_get_public_key_expire_date_from_config(uid_hash):
    '''Get the asymmetric expire date.
    '''
    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('config'):
        affected_rows = cursor.execute(
            "SELECT aexpire_date FROM %s WHERE uid_hash='%s' LIMIT 1" % (t, uid_hash))
        if affected_rows != 0:
            expire_time = cursor.fetchone()[0]
            _sql_close(db)
            return expire_time

    _sql_close(db)
    return None


def sql_get_public_key_expire_date_from_public_key(uid_hash):
    '''Get the asymmetric expire date.
    '''
    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('public_key'):
        affected_rows = cursor.execute(
            "SELECT expire_time FROM %s WHERE uid_hash='%s' LIMIT 1" % (t, uid_hash))
        if affected_rows != 0:
            expire_time = cursor.fetchone()[0]
            _sql_close(db)
            return expire_time

    _sql_close(db)
    return None


def sql_get_public_key(uid_hash):
    '''Get the public key by uid_hash.
    This function can only be used by /account command to show the user's public key.

    Returns:
        public_key(str).
        None.
    '''
    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('public_key'):
        affected_rows = cursor.execute(
            "SELECT public_key FROM %s WHERE uid_hash='%s' LIMIT 1" % (t, uid_hash))
        if affected_rows != 0:
            # ('xxxxxxxx',)
            public_key = cursor.fetchone()[0]
            _sql_close(db)
            return public_key

    _sql_close(db)
    return None


def sql_get_secret_key(secret_key_hash):
    '''Get the secret key by uid_hash.

    Returns:
        secret_key(str).
        -1(int): auto delete the secret_key which rearch max decryption time.
    '''
    db = _sql_connect()
    cursor = db.cursor()

    remain_time = sql_get_remaining_decryption_times_secret_key(
        secret_key_hash)
    if not remain_time:
        return None

    remain_time = int(remain_time)
    # print(remain_time)
    if remain_time > 0:
        sql_update_remaining_decryption_time_secret_key(secret_key_hash)

    elif remain_time == 0:
        secret_key_hash_list = list()
        secret_key_hash_list.append(secret_key_hash)
        sql_delete_expired_secret_key(secret_key_hash_list)
        return None

    for t in _sql_all_table_name('secret_key'):
        affected_rows = cursor.execute(
            "SELECT secret_key FROM %s WHERE secret_key_hash='%s' LIMIT 1" % (t, secret_key_hash))
        if affected_rows != 0:
            secret_key = cursor.fetchone()[0]
            _sql_close(db)
            return secret_key

    _sql_close(db)
    return None


def sql_get_remaining_decryption_times_secret_key(secret_key_hash):
    '''
    '''
    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('secret_key'):
        affected_rows = cursor.execute(
            "SELECT remain_time FROM %s WHERE secret_key_hash='%s' LIMIT 1" % (t, secret_key_hash))
        if affected_rows != 0:
            remain_time = cursor.fetchone()[0]
            _sql_close(db)
            return remain_time

    _sql_close(db)
    return None


def sql_get_remaining_decryption_times_cipher_text(cipher_text_hash):
    '''
    '''
    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('cipher_text'):
        affected_rows = cursor.execute(
            "SELECT remain_time FROM %s WHERE cipher_text_hash='%s' LIMIT 1" % (t, cipher_text_hash))
        if affected_rows != 0:
            remain_time = cursor.fetchone()[0]
            _sql_close(db)
            return remain_time

    _sql_close(db)
    return None


def sql_get_cipher_text(cipher_text_hash):
    '''Get the secret key by uid_hash.

    Args:
        cipher_text_hash(str).

    Returns:
        cipher_text(str).
        None: this cipher_text is delete by max decryption time.
    '''
    db = _sql_connect()
    cursor = db.cursor()

    try:
        remain_time = int(
            sql_get_remaining_decryption_times_cipher_text(cipher_text_hash))
    except Exception:
        # Can not get the remain_decryption time.
        return None

    # print(remain_time)

    if remain_time > 0:
        sql_update_remaining_decryption_time_cipher_text(cipher_text_hash)
    elif remain_time == 0:
        cipher_text_hash_list = list()
        cipher_text_hash_list.append(cipher_text_hash)
        sql_delete_expired_cipher_text(cipher_text_hash_list)
        return None

    for t in _sql_all_table_name('cipher_text'):
        affected_rows = cursor.execute(
            "SELECT cipher_text FROM %s WHERE cipher_text_hash='%s' LIMIT 1" % (t, cipher_text_hash))
        if affected_rows != 0:
            cipher_text = cursor.fetchone()[0]
            _sql_close(db)
            return cipher_text

    _sql_close(db)
    return None


def sql_update_remaining_decryption_time_config(uid_hash, update_vaule):
    '''Update the user remain time in config table.
    '''
    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('config'):
        try:
            cursor.execute(
                "UPDATE %s SET remain_time='%d' WHERE uid_hash='%s' LIMIT 1" % (t, update_vaule, uid_hash))
            # affected_rows = cursor.execute(
            #     "UPDATE %s SET remain_time='%d' WHERE uid_hash='%s' LIMIT 1" % (t, update_vaule, uid_hash))
            # print(affected_rows)
        except Exception:
            _sql_rollback(db)
            _sql_close(db)
            return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_get_remaining_decryption_times_config(uid_hash):
    '''Get the remain time from config table.
    '''
    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('config'):
        affected_rows = cursor.execute(
            "SELECT remain_time FROM %s WHERE uid_hash='%s' LIMIT 1" % (t, uid_hash))
        if affected_rows != 0:
            remain_time = cursor.fetchone()[0]
            _sql_close(db)
            return remain_time

    _sql_close(db)
    return None


def sql_update_remaining_decryption_time_secret_key(secret_key_hash):
    '''Auto make the remaining time - 1.
    '''

    db = _sql_connect()
    cursor = db.cursor()

    remain_time = sql_get_remaining_decryption_times_secret_key(
        secret_key_hash)
    if not remain_time:
        return None

    remain_time = int(remain_time)
    remain_time = remain_time - 1

    for t in _sql_all_table_name('secret_key'):
        try:
            cursor.execute(
                "UPDATE %s SET remain_time='%d' WHERE secret_key_hash='%s' LIMIT 1" % (t, remain_time, secret_key_hash))
        except Exception:
            _sql_rollback(db)
            _sql_close(db)
            return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_update_remaining_decryption_time_cipher_text(cipher_text_hash):
    '''Auto make the remaining time - 1.
    '''

    db = _sql_connect()
    cursor = db.cursor()

    # remain_time = int(
    #     sql_get_remaining_decryption_times_cipher_text(cipher_text_hash))
    # remain_time = remain_time - 1

    for t in _sql_all_table_name('cipher_text'):
        try:
            cursor.execute(
                "UPDATE %s SET remain_time=remain_time-1 WHERE cipher_text_hash='%s' LIMIT 1" % (t, cipher_text_hash))
        except Exception:
            # print('errror')
            _sql_rollback(db)
            _sql_close(db)
            return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_update_expired_public_key(uid_hash_list, public_key):
    '''Update the key database.

    Args:
        uid_hash_list(list).
        public_key(str).

    Returns:
        -1: failed.
        0: success.
        1: user not existed.
    '''
    not_allow_uid_list = list()
    for uid_hash in uid_hash_list:
        if _sql_check_uid(uid_hash) != 1:
            not_allow_uid_list.append(uid_hash)

    for n in not_allow_uid_list:
        uid_hash_list.remove(n)

    # uid_hash exists.
    db = _sql_connect()
    cursor = db.cursor()
    now_time = int(time.time())
    public_key_expire_time = sql_get_public_key_expire_date_from_config(
        uid_hash)
    expire_time = now_time + int(public_key_expire_time)

    for p in _sql_all_table_name('public_key'):
        for ni in uid_hash_list:
            try:
                cursor.execute(
                    "UPDATE %s SET public_key='%s', expire_time='%d' WHERE uid_hash='%s' LIMIT 1" % (p, public_key, expire_time, ni))
            except Exception:
                _sql_rollback(db)
                _sql_close(db)
                return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_delete_expired_secret_key(secret_key_hash_list):
    '''Update the e_secret_key_x database.

    Args:
        secret_key_hash_list(list).

    Returns:
        -1: failed.
        0: success.
        1: user not existed.
    '''

    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('secret_key'):
        for s in secret_key_hash_list:
            try:
                cursor.execute(
                    "DELETE FROM %s WHERE secret_key_hash='%s' LIMIT 1" % (t, s))
            except Exception:
                _sql_rollback(db)
                _sql_close(db)
                return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_delete_expired_nonce(nonce_hash_list):
    '''Update the e_nonce_x database.

    Args:
        nonce_hash_list(list).

    Returns:
        -1: failed.
        0: success.
    '''
    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('nonce'):
        for n in nonce_hash_list:
            try:
                cursor.execute("DELETE FROM %s WHERE nonce_hash='%s' LIMIT 1" %
                               (t, n))
            except Exception:
                _sql_rollback(db)
                _sql_close(db)
                return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_delete_expired_cipher_text(cipher_text_hash_list):
    '''Update the e_cipher_text_x database.

    Args:
        cipher_text_hash_list(list).

    Returns:
        -1: failed.
        0: success.
    '''
    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('cipher_text'):
        for c in cipher_text_hash_list:
            try:
                cursor.execute("DELETE FROM %s WHERE cipher_text_hash='%s' LIMIT 1" %
                               (t, c))
            except Exception:
                _sql_rollback(db)
                _sql_close(db)
                return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_insert_secret_key(uid_hash, secret_key_hash, secret_key):

    if _sql_check_uid(uid_hash) != 1:
        return 1

    db = _sql_connect()
    cursor = db.cursor()
    now_time = int(time.time())
    secret_key_expire_time = sql_get_secret_key_expire_date_from_config(
        uid_hash)
    expire_time = now_time + int(secret_key_expire_time)
    secret_key_table_name = _sql_one_table_name('secret_key')

    remain_time = int(sql_get_remaining_decryption_times_config(uid_hash))

    try:
        cursor.execute("INSERT INTO %s (secret_key_hash, secret_key, expire_time, remain_time) VALUES ('%s', '%s', '%d', '%d')" % (
            secret_key_table_name, secret_key_hash, secret_key, expire_time, remain_time))
    except Exception:
        _sql_rollback(db)
        _sql_close(db)
        return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_update_symmetric_expire_date(uid_hash, expire_time):
    '''Update the config database.

    Args:
        uid_hash(str).
        expire_time(int).

    Returns:
        -1: failed.
        0: success.
        1: user not existed.
    '''

    if _sql_check_uid(uid_hash) != 1:
        return 1

    expire_time = int(expire_time)
    if expire_time > config.DEFAULT_MAX_EXPIRE_TIME:
        expire_time = config.DEFAULT_ASYMMETRIC_EXPIRE_TIME

    if expire_time < config.DEFAULT_MIN_EXPIRE_TIME:
        expire_time = config.DEFAULT_MIN_EXPIRE_TIME

    db = _sql_connect()
    cursor = db.cursor()
    for t in _sql_all_table_name('config'):
        # expire_time = int(time.time()) + date
        try:
            cursor.execute("UPDATE %s SET sexpire_date='%s' WHERE uid_hash='%s' LIMIT 1" % (
                t, expire_time, uid_hash))
        except Exception:
            _sql_rollback(db)
            _sql_close(db)
            return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_update_asymmetric_expire_date(uid_hash, expire_time):
    '''Update the config database.

    Args:
        uid_hash(str).
        expire_time(int).

    Returns:
        -1: failed.
        0: success.
        1: user not existed.
    '''
    if _sql_check_uid(uid_hash) != 1:
        return 1

    db = _sql_connect()
    cursor = db.cursor()

    expire_time = int(expire_time)
    if expire_time > config.DEFAULT_MAX_EXPIRE_TIME:
        expire_time = config.DEFAULT_ASYMMETRIC_EXPIRE_TIME

    if expire_time < config.DEFAULT_MIN_EXPIRE_TIME:
        expire_time = config.DEFAULT_MIN_EXPIRE_TIME

    for t in _sql_all_table_name('config'):
        # expire_time = int(time.time()) + date
        try:
            cursor.execute("UPDATE %s SET aexpire_date='%s' WHERE uid_hash='%s' LIMIT 1" % (
                t, expire_time, uid_hash))
        except Exception:
            _sql_rollback(db)
            _sql_close(db)
            return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_get_encryption_mode(uid_hash):
    '''Get the user encryption mode.

    Retruns:
        encryption_mode(int).
    '''
    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('config'):
        affected_rows = cursor.execute(
            "SELECT encryption_mode FROM %s WHERE uid_hash='%s' LIMIT 1" % (t, uid_hash))
        if affected_rows != 0:
            encryption_mode = cursor.fetchone()[0]
            _sql_close(db)
            return int(encryption_mode)

    _sql_close(db)
    return None


def sql_get_emoji_mode(uid_hash):
    '''Get the user encryption mode.

    Retruns:
        emoji_mode(int):
            1 = enabled.
            0 = disabled.
    '''
    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('config'):
        affected_rows = cursor.execute(
            "SELECT emoji_mode FROM %s WHERE uid_hash='%s' LIMIT 1" % (t, uid_hash))
        if affected_rows != 0:
            emoji_mode = cursor.fetchone()[0]
            _sql_close(db)
            return int(emoji_mode)

    _sql_close(db)
    return None


def sql_update_emoji_mode(uid_hash, emoji_mode):
    '''1 => 0, 0 => 1
    '''
    if _sql_check_uid(uid_hash) != 1:
        return -1

    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('config'):
        try:
            cursor.execute("UPDATE %s SET emoji_mode='%s' WHERE uid_hash='%s' LIMIT 1" % (
                t, emoji_mode, uid_hash))
        except Exception:
            _sql_rollback(db)
            _sql_close(db)
            return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_update_encryption_mode(uid_hash, encryption_mode):
    '''Update the user encryption mode.

    Args:
        uid_hash(str).
        encryption_mode(int).

    Returns:
        -1: failed.
        0: success.
        1: user not existed.
    '''
    if _sql_check_uid(uid_hash) != 1:
        return -1

    db = _sql_connect()
    cursor = db.cursor()

    for t in _sql_all_table_name('config'):
        try:
            cursor.execute("UPDATE %s SET encryption_mode='%s' WHERE uid_hash='%s' LIMIT 1" % (
                t, encryption_mode, uid_hash))
        except Exception:
            _sql_rollback(db)
            _sql_close(db)
            return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_insert_cipher_text(uid_hash, cipher_text_hash, cipher_text):
    '''Insert the nonce_hash_hex, nonce_hex to nonce table (only for symmertic encryption).

    Args:
        uid_hash(str)
        cipher_text_hash_hex(str).
        cipher_text(str).

    Returns:
        -1: failed.
        0: success.
    '''

    if _sql_check_uid(uid_hash) != 1:
        return -1

    db = _sql_connect()
    cursor = db.cursor()
    cipher_text_table_name = _sql_one_table_name('cipher_text')
    # print(cipher_text_table_name)
    now_time = int(time.time())
    # Only for the symmertic encrytion.
    expire_time = now_time + config.DEFAULT_SYMMETRIC_EXPIRE_TIME
    remain_time = int(sql_get_remaining_decryption_times_config(uid_hash))

    try:
        cursor.execute("INSERT INTO %s (cipher_text_hash, cipher_text, expire_time, remain_time) VALUES ('%s', '%s', '%d', '%d')" % (
            cipher_text_table_name, cipher_text_hash, cipher_text, expire_time, remain_time))
    except Exception:
        _sql_rollback(db)
        _sql_close(db)
        return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_insert_nonce(uid_hash, nonce_hash, nonce):
    '''Insert the nonce_hash_hex, nonce_hex to nonce table.

    Args:
        uid_hash(str).
        nonce_hash(str).
        nonce(str).

    Returns:
        -1: failed.
        0: success.
    '''

    if _sql_check_uid(uid_hash) != 1:
        return -1

    db = _sql_connect()
    cursor = db.cursor()
    nonce_table_name = _sql_one_table_name('nonce')
    now_time = int(time.time())
    # expire_time = now_time + config.DEFAULT_NONCE_EXPIRE_DATE
    encryption_mode = sql_get_encryption_mode(uid_hash)
    if encryption_mode == config.ASYMMETRIC_ENCRYPTION_MODE:
        public_key_expire_time = sql_get_public_key_expire_date_from_config(
            uid_hash)
        expire_time = now_time + public_key_expire_time

    elif encryption_mode == config.SYMMETRIC_ENCRYPTION_MODE:
        secret_key_expire_time = sql_get_secret_key_expire_date_from_config(
            uid_hash)
        expire_time = now_time + secret_key_expire_time

    try:
        cursor.execute("INSERT INTO %s (nonce_hash, nonce, expire_time) VALUES ('%s', '%s', '%d')" % (
            nonce_table_name, nonce_hash, nonce, expire_time))
    except Exception:
        _sql_rollback(db)
        _sql_close(db)
        return -1

    _sql_commit(db)
    _sql_close(db)
    return 0


def sql_nonce_query(nonce_hash):
    '''Query the nonce_str by nonce_str_hash

    Args:
        nonce_hash_hex(str).

    Returns:
        success: nonce_hex(str).
        failed: None.
    '''
    db = _sql_connect()
    cursor = db.cursor()
    for t in _sql_all_table_name('nonce'):
        affected_rows = cursor.execute(
            "SELECT nonce FROM %s WHERE nonce_hash='%s' LIMIT 1" % (t, nonce_hash))
        if affected_rows != 0:
            nonce = cursor.fetchone()[0]
            _sql_close(db)
            return nonce

    _sql_close(db)
    return None


def sql_delete_user_all_key(uid_hash):
    '''Delete all the uid key and uid in all table.

    Args:
        uid_hash(str).

    Returns:
        -1: failed.
        0: success.
    '''
    db = _sql_connect()
    cursor = db.cursor()
    sql_status = 0

    for u in _sql_all_table_name('user'):
        try:
            cursor.execute("DELETE FROM %s WHERE uid_hash='%s'" %
                           (u, uid_hash))
        except Exception:
            sql_status = -1

    for c in _sql_all_table_name('config'):
        try:
            cursor.execute("DELETE FROM %s WHERE uid_hash='%s'" %
                           (c, uid_hash))
        except Exception:
            sql_status = -1

    for p in _sql_all_table_name('public_key'):
        try:
            cursor.execute("DELETE FROM %s WHERE uid_hash='%s'" %
                           (p, uid_hash))
        except Exception:
            sql_status = -1

    _sql_commit(db)
    _sql_close(db)
    return sql_status


def sql_truncate_all_table():
    '''Self destroy the database.
    '''
    db = _sql_connect()
    cursor = db.cursor()
    for u in _sql_all_table_name('user'):
        try:
            cursor.execute("TRUNCATE TABLE %s" % u)
        except Exception:
            pass

    for k in _sql_all_table_name('key'):
        try:
            cursor.execute("TRUNCATE TABLE %s" % k)
        except Exception:
            pass

    for c in _sql_all_table_name('config'):
        try:
            cursor.execute("TRUNCATE TABLE %s" % c)
        except Exception:
            pass

    for p in _sql_all_table_name('public_key'):
        try:
            cursor.execute("TRUNCATE TABLE %s" % p)
        except Exception:
            pass

    _sql_commit(db)
    _sql_close(db)


def sql_status():
    '''Show the sql table status.
    'user': get all the e_user_x name.
    'key': get the all e_key_x table name.
    'config': get all the e_config_x table name.
    'nonce': get all the e_nonce_x table name.
    'public_key': get all the e_public_key_x table name.
    '''

    return_list = list()
    for t in _sql_all_table_name('user'):
        status_dict = dict()
        rows = _sql_table_rows(t)
        status_dict['table_name'] = t
        status_dict['rows'] = int(rows)
        return_list.append(status_dict)

    for t in _sql_all_table_name('public_key'):
        status_dict = dict()
        rows = _sql_table_rows(t)
        status_dict['table_name'] = t
        status_dict['rows'] = int(rows)
        return_list.append(status_dict)

    for t in _sql_all_table_name('secret_key'):
        status_dict = dict()
        rows = _sql_table_rows(t)
        status_dict['table_name'] = t
        status_dict['rows'] = int(rows)
        return_list.append(status_dict)

    for t in _sql_all_table_name('config'):
        status_dict = dict()
        rows = _sql_table_rows(t)
        status_dict['table_name'] = t
        status_dict['rows'] = int(rows)
        return_list.append(status_dict)

    for t in _sql_all_table_name('nonce'):
        status_dict = dict()
        rows = _sql_table_rows(t)
        status_dict['table_name'] = t
        status_dict['rows'] = int(rows)
        return_list.append(status_dict)

    for t in _sql_all_table_name('cipher_text'):
        status_dict = dict()
        rows = _sql_table_rows(t)
        status_dict['table_name'] = t
        status_dict['rows'] = int(rows)
        return_list.append(status_dict)

    return return_list


def main():
    return


if __name__ == "__main__":
    main()
