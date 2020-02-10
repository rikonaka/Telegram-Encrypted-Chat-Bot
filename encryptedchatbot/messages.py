#!/usr/bin/env python3

import datetime
import random

from telegram import ParseMode
from telegram.ext import DispatcherHandlerStop
from telegram.ext.dispatcher import run_async

from encryptedchatbot import keyboards
from encryptedchatbot import config
from encryptedchatbot.utils import only_admin
from encryptedchatbot.utils import check_admin
from encryptedchatbot.utils import is_maintenance
from encryptedchatbot.utils import check_string
from encryptedchatbot import sql
from encryptedchatbot import encrypt


def symmetric_encrypt_inline(update, context, uid_hash, text):
    '''Never use @run_asyn here.'''

    if sql.sql_check_user(uid_hash) != 1:
        # Make sure the inline user is registerd.
        return -1

    secret_key_bytes = encrypt.symmetric_key_generate()
    secret_key_str = encrypt.convert_bytes_to_str(secret_key_bytes)
    secret_key_str_hash = encrypt.sha256_hash(secret_key_str)
    sql.sql_insert_secret_key(uid_hash, secret_key_str_hash, secret_key_str)

    encrypt_result_dict = encrypt.symmetric_encryption(
        secret_key_bytes, text)

    if encrypt_result_dict:
        cipher_text_bytes = encrypt_result_dict['cipher_text']
        cipher_text_str = encrypt.convert_bytes_to_str(
            cipher_text_bytes)

        nonce_bytes = encrypt_result_dict['nonce']
        nonce_str = encrypt.convert_bytes_to_str(nonce_bytes)
        nonce_str_hash = encrypt.sha256_hash(nonce_str)
        if sql.sql_insert_nonce(uid_hash, nonce_str_hash, nonce_str) != 0:
            result_str = config.SERVER_ERROR_EXPRESSION
        else:
            result_str = 'sencrypted[%s%s%s]' % (
                nonce_str_hash, secret_key_str_hash, cipher_text_str)

    else:
        result_str = config.SERVER_ERROR_EXPRESSION

    return result_str


def symmetric_decrypt_inline(update, context, uid_hash, text):
    '''Symmetric encryption decrypt message here.
    '''

    if not text:
        return None

    try:
        cipher_data = text.split('sencrypted')[1][1:-1]
        # print('messages[cipher_data]: ' + cipher_data)
    except IndexError:
        return None

    nonce_str_hash = cipher_data[0:64]
    secret_key_str_hash = cipher_data[64:128]
    cipher_text_str = cipher_data[128:-1] + cipher_data[-1]

    nonce_str = sql.sql_nonce_query(nonce_str_hash)
    secret_key_str = sql.sql_get_secret_key(secret_key_str_hash)
    # print('message(secret_key_str): ' + secret_key_str)

    if secret_key_str:
        secret_key_bytes = encrypt.convert_str_to_bytes(secret_key_str)
        nonce_bytes = encrypt.convert_str_to_bytes(nonce_str)
        cipher_text_bytes = encrypt.convert_str_to_bytes(cipher_text_str)

        plain_text = encrypt.symmetric_decryption(
            secret_key_bytes, nonce_bytes, cipher_text_bytes)

        if plain_text == None:
            plain_text = 'Your cipher text is longer than 256. ・ω・'

        # elif 'photo[' in plain_text and ']' in plain_text:
        #     file_id = plain_text[6:-1]
        #     update.message.reply_photo(photo=file_id)
    elif not secret_key_str:
        # try:
        #     bot.editMessageText(
        #         message_id=update.callback_query.message.message_id,
        #         chat_id=update.callback_query.message.chat.id,
        #         text='This ciphertext has expired. %s' % (
        #             config.GOOD_EXPRESSION),
        #         parse_mode=ParseMode.HTML,
        #         # reply_markup=keyboards.inline_chtm_keyboard()
        #     )
        # except Exception:
        #     pass
        plain_text = 'Sorry, we can\'t decrypt this ciphertext forever.'

    return plain_text


@run_async
def symmetric_decrypt_message(update, context, text):
    '''Symmetric encryption decrypt message here.
    '''

    if not text:
        plain_text = 'Sorry, we can\'t decrypt this ciphertext.'
        update.message.reply_text(text=plain_text, parse_mode=ParseMode.HTML)
        return -1

    try:
        cipher_data = text.split('sencrypted')[1][1:-1]
    except IndexError:
        return -1

    if len(cipher_data) == 0:
        return -1

    nonce_str_hash = cipher_data[0:64]
    if not check_string(nonce_str_hash) or len(nonce_str_hash) == 0:
        return -1

    secret_key_str_hash = cipher_data[64:128]
    if not check_string(secret_key_str_hash) or len(secret_key_str_hash) == 0:
        return -1

    cipher_text_str = cipher_data[128:-1] + cipher_data[-1]
    if not check_string(cipher_text_str) or len(cipher_text_str) == 0:
        return -1

    nonce_str = sql.sql_nonce_query(nonce_str_hash)
    secret_key_str = sql.sql_get_secret_key(secret_key_str_hash)
    if secret_key_str:
        secret_key_bytes = encrypt.convert_str_to_bytes(secret_key_str)
        nonce_bytes = encrypt.convert_str_to_bytes(nonce_str)
        cipher_text_bytes = encrypt.convert_str_to_bytes(cipher_text_str)

        plain_text = encrypt.symmetric_decryption(
            secret_key_bytes, nonce_bytes, cipher_text_bytes)

        if plain_text == None:
            plain_text = 'Sorry, we can\'t decrypt this ciphertext.'

        elif 'photo[' in plain_text and ']' in plain_text:
            file_id = plain_text[6:-1]
            if not check_string(file_id):
                return -1

            update.message.reply_photo(photo=file_id)
            return 0

    elif not secret_key_str:
        # try:
        #     bot.editMessageText(
        #         message_id=update.callback_query.message.message_id,
        #         chat_id=update.callback_query.message.chat.id,
        #         text='This ciphertext has expired. %s' % (
        #             config.GOOD_EXPRESSION),
        #         parse_mode=ParseMode.HTML,
        #         # reply_markup=keyboards.inline_chtm_keyboard()
        #     )
        # except Exception:
        #     pass
        plain_text = 'Sorry, we can\'t decrypt this ciphertext forever.'

    update.message.reply_text(text=plain_text, parse_mode=ParseMode.HTML)
    return 0


@run_async
def asymmetric_decrypt_message(update, context, text):
    '''As you see'''

    message = update.message
    uid = message.from_user.id
    uid_hash = encrypt.blake2b_hash(str(uid))

    if config.private_key_dict.__contains__(uid_hash):
        if config.private_key_dict[uid_hash] == 'decrypt':
            # Check the private key length.
            user_private_key_str = (str(message.text)).strip()
            if len(user_private_key_str) != 64 or not check_string(user_private_key_str):
                text = 'Please check your private key value.'
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)
                config.private_key_dict.pop(uid_hash)
                config.public_key_dict.pop(uid_hash)
                config.nonce_dict.pop(uid_hash)
                config.cipher_txt_dict.pop(uid_hash)
                return

            nonce_bytes = encrypt.convert_str_to_bytes(
                config.nonce_dict[uid_hash])
            cipher_text_bytes = encrypt.convert_str_to_bytes(
                config.cipher_txt_dict[uid_hash])
            # We get the target uid's public key.
            target_public_key_str = config.public_key_dict[uid_hash]
            if not target_public_key_str:
                text = 'No such user.'
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)
                return

            user_private_key_bytes = encrypt.convert_str_to_bytes(
                user_private_key_str)
            target_public_key_bytes = encrypt.convert_str_to_bytes(
                target_public_key_str)
            # print('d-target-pk: ' + target_public_key_str)
            plain_text = encrypt.asymmetric_decryption(
                user_private_key_bytes, target_public_key_bytes, nonce_bytes, cipher_text_bytes)

            config.private_key_dict.pop(uid_hash)
            config.public_key_dict.pop(uid_hash)
            config.nonce_dict.pop(uid_hash)
            config.cipher_txt_dict.pop(uid_hash)
            config.command_expire_list.remove(uid_hash)
            # print(plain_text)
            if plain_text == None:
                update.message.reply_text(
                    text='Sorry, we can\'t decrypt this ciphertext.', parse_mode=ParseMode.HTML)

            elif 'photo[' in plain_text and ']' in plain_text:
                file_id = plain_text[6:-1]
                update.message.reply_photo(photo=file_id)

            update.message.reply_text(
                text=plain_text, parse_mode=ParseMode.HTML)

    else:
        try:
            cipher_data = text.split('aencrypted')[1][1:-1]
        except IndexError:
            return

        if len(cipher_data) == 0:
            return -1

        nonce_str_hash = cipher_data[0:64]
        if not check_string(nonce_str_hash) or len(nonce_str_hash) == 0:
            return -1
        target_uid_hash = cipher_data[64:128]
        if not check_string(target_uid_hash) or len(target_uid_hash) == 0:
            return -1
        cipher_text_str = cipher_data[128:-1] + cipher_data[-1]
        if not check_string(cipher_text_str) or len(cipher_text_str) == 0:
            return -1

        nonce_str = sql.sql_nonce_query(nonce_str_hash)
        config.private_key_dict[uid_hash] = 'decrypt'
        config.public_key_dict[uid_hash] = sql.sql_get_public_key(
            target_uid_hash)
        config.nonce_dict[uid_hash] = nonce_str
        config.cipher_txt_dict[uid_hash] = cipher_text_str
        config.command_expire_list.append(uid_hash)

        text = '[decrypt]Please input your private key.'
        update.message.reply_text(text=text, parse_mode=ParseMode.HTML)


@run_async
def symmetric_encrypt_message_emoji(update, context, text):
    '''Make the encryption result as emoji
    '''
    message = update.message
    uid = message.from_user.id
    uid_hash = encrypt.blake2b_hash(str(uid))

    secret_key_bytes = encrypt.symmetric_key_generate()
    secret_key_str = encrypt.convert_bytes_to_str(secret_key_bytes)
    secret_key_str_hash = encrypt.sha256_hash(secret_key_str)
    sql.sql_insert_secret_key(uid_hash, secret_key_str_hash, secret_key_str)

    encrypt_result_dict = encrypt.symmetric_encryption(
        secret_key_bytes, text)

    if encrypt_result_dict:
        cipher_text_bytes = encrypt_result_dict['cipher_text']
        cipher_text_str = encrypt.convert_bytes_to_str(
            cipher_text_bytes)

        nonce_bytes = encrypt_result_dict['nonce']
        nonce_str = encrypt.convert_bytes_to_str(nonce_bytes)
        nonce_str_hash = encrypt.sha256_hash(nonce_str)
        if sql.sql_insert_nonce(uid_hash, nonce_str_hash, nonce_str) != 0:
            text = config.SERVER_ERROR_EXPRESSION
        else:
            text = '%s%s%s' % (
                nonce_str_hash, secret_key_str_hash, cipher_text_str)

    else:
        text = config.SERVER_ERROR_EXPRESSION

    # text = encrypt.convert_str_to_emoji(text)
    text = encrypt.convert_str_to_emoji_c(text)
    update.message.reply_text(text=text, parse_mode=ParseMode.HTML)


@run_async
def symmetric_encrypt_message(update, context, text):

    message = update.message
    uid = message.from_user.id
    uid_hash = encrypt.blake2b_hash(str(uid))

    secret_key_bytes = encrypt.symmetric_key_generate()
    secret_key_str = encrypt.convert_bytes_to_str(secret_key_bytes)
    secret_key_str_hash = encrypt.sha256_hash(secret_key_str)
    sql.sql_insert_secret_key(uid_hash, secret_key_str_hash, secret_key_str)

    encrypt_result_dict = encrypt.symmetric_encryption(
        secret_key_bytes, text)

    if encrypt_result_dict:
        cipher_text_bytes = encrypt_result_dict['cipher_text']
        cipher_text_str = encrypt.convert_bytes_to_str(
            cipher_text_bytes)

        nonce_bytes = encrypt_result_dict['nonce']
        nonce_str = encrypt.convert_bytes_to_str(nonce_bytes)
        nonce_str_hash = encrypt.sha256_hash(nonce_str)
        if sql.sql_insert_nonce(uid_hash, nonce_str_hash, nonce_str) != 0:
            text = config.SERVER_ERROR_EXPRESSION
        else:
            text = 'sencrypted[%s%s%s]' % (
                nonce_str_hash, secret_key_str_hash, cipher_text_str)

    else:
        text = config.SERVER_ERROR_EXPRESSION

    update.message.reply_text(text=text, parse_mode=ParseMode.HTML)


@run_async
def asymmetric_encrypt_message(update, context, text):
    '''Start doing core work now.'''

    message = update.message
    uid = message.from_user.id
    uid_hash = encrypt.blake2b_hash(str(uid))

    if config.private_key_dict.__contains__(uid_hash):
        if config.private_key_dict[uid_hash] == 'encrypt':
            # Check the private key length.
            user_private_key_str = (str(message.text)).strip()
            if len(user_private_key_str) != 64:
                text = 'Please check your private key value.'
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)
                config.private_key_dict.pop(uid_hash)
                return

            text = '[encrypt]Please input the target user id.'
            update.message.reply_text(text=text, parse_mode=ParseMode.HTML)
            config.private_key_dict[uid_hash] = user_private_key_str
            return

        else:
            target_uid = (str(message.text)).strip()
            target_uid_hash = encrypt.blake2b_hash(target_uid)
            # print('e-target_hash: ' + target_uid_hash)
            target_public_key_str = sql.sql_get_public_key(
                target_uid_hash)
            if target_public_key_str == None:
                text = 'Sorry, we can not found such user.'
                update.message.reply_text(text=text, parse_mode=ParseMode.HTML)
                return

            config.public_key_dict[uid_hash] = target_public_key_str
            user_private_key_bytes = encrypt.convert_str_to_bytes(
                config.private_key_dict[uid_hash])
            target_public_key_bytes = encrypt.convert_str_to_bytes(
                config.public_key_dict[uid_hash])
            encrypt_result_dict = encrypt.asymmetric_encryption(
                user_private_key_bytes, target_public_key_bytes, config.plain_text_dict[uid_hash])

            if encrypt_result_dict:
                cipher_text_bytes = encrypt_result_dict['cipher_text']
                cipher_text_str = encrypt.convert_bytes_to_str(
                    cipher_text_bytes)
                nonce_bytes = encrypt_result_dict['nonce']
                nonce_str = encrypt.convert_bytes_to_str(nonce_bytes)
                nonce_str_hash = encrypt.sha256_hash(nonce_str)

                if sql.sql_insert_nonce(uid_hash, nonce_str_hash, nonce_str):
                    text = config.SERVER_ERROR_EXPRESSION
                else:
                    text = 'aencrypted[%s%s%s]' % (
                        nonce_str_hash, uid_hash, cipher_text_str)
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)

            config.private_key_dict.pop(uid_hash)
            config.public_key_dict.pop(uid_hash)
            config.plain_text_dict.pop(uid_hash)
            config.command_expire_list.remove(uid_hash)

    else:
        config.plain_text_dict[uid_hash] = text
        config.private_key_dict[uid_hash] = 'encrypt'
        config.command_expire_list.append(uid_hash)
        text = '[encrypt]Please input your private key.'
        update.message.reply_text(text=text, parse_mode=ParseMode.HTML)


@run_async
@is_maintenance
def process_message_private(update, context):
    '''For private chat use.'''
    message = update.message
    uid = message.from_user.id
    uid_hash = encrypt.blake2b_hash(str(uid))

    # Ignore the command message.
    if message.text and message.text[0] == r'/':
        return

    if sql.sql_check_user(uid_hash) != 1:
        # If the not registed user want to decrypted this message.
        # Be safety considering, not do decrypt job.
        plain_text = 'Sorry, we can\'t decrypt this ciphertext'
        update.message.reply_text(
            text=plain_text, parse_mode=ParseMode.HTML)
        return

    encryption_mode = sql.sql_get_encryption_mode(uid_hash)
    if config.expire_date_unit_select_dict.__contains__(uid_hash):
        if encryption_mode == config.SYMMETRIC_ENCRYPTION_MODE:
            if config.expire_date_unit_select_dict[uid_hash] == 'second':
                try:
                    second = int(message.text)
                except Exception:
                    text = '<b>Please check your input.</b>'
                    update.message.reply_text(
                        text=text, parse_mode=ParseMode.HTML)
                    return

                sql.sql_update_symmetric_expire_date(uid_hash, second)
                config.expire_date_unit_select_dict.pop(uid_hash)
                config.command_expire_list.remove(uid_hash)
                text = '<b>Update success, please use /account command to see.</b>'
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)

            elif config.expire_date_unit_select_dict[uid_hash] == 'minute':
                try:
                    minute = int(message.text) * 60
                except Exception:
                    text = '<b>Please check your input.</b>'
                    update.message.reply_text(
                        text=text, parse_mode=ParseMode.HTML)
                    return

                sql.sql_update_symmetric_expire_date(uid_hash, minute)
                config.expire_date_unit_select_dict.pop(uid_hash)
                config.command_expire_list.remove(uid_hash)
                text = '<b>Update success, please use /account command to see.</b>'
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)

            elif config.expire_date_unit_select_dict[uid_hash] == 'hour':
                try:
                    hour = int(message.text) * 60 * 60
                except Exception:
                    text = '<b>Please check your input.</b>'
                    update.message.reply_text(
                        text=text, parse_mode=ParseMode.HTML)
                    return

                sql.sql_update_symmetric_expire_date(uid_hash, hour)
                config.expire_date_unit_select_dict.pop(uid_hash)
                config.command_expire_list.remove(uid_hash)
                text = '<b>Update success, please use /account command to see.</b>'
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)

            elif config.expire_date_unit_select_dict[uid_hash] == 'day':
                try:
                    day = int(message.text) * 60 * 60 * 24
                except Exception:
                    text = '<b>Please check your input.</b>'
                    update.message.reply_text(
                        text=text, parse_mode=ParseMode.HTML)
                    return

                sql.sql_update_symmetric_expire_date(uid_hash, day)
                config.expire_date_unit_select_dict.pop(uid_hash)
                config.command_expire_list.remove(uid_hash)
                text = '<b>Update success, please use /account command to see.</b>'
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)
        if encryption_mode == config.ASYMMETRIC_ENCRYPTION_MODE:
            if config.expire_date_unit_select_dict[uid_hash] == 'second':
                try:
                    second = int(message.text)
                except Exception:
                    text = '<b>Please check your input.</b>'
                    update.message.reply_text(
                        text=text, parse_mode=ParseMode.HTML)
                    return

                sql.sql_update_asymmetric_expire_date(uid_hash, second)
                config.expire_date_unit_select_dict.pop(uid_hash)
                config.command_expire_list.remove(uid_hash)
                text = '<b>Update success, please use /account command to see.</b>'
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)

            elif config.expire_date_unit_select_dict[uid_hash] == 'minute':
                try:
                    minute = int(message.text) * 60
                except Exception:
                    text = '<b>Please check your input.</b>'
                    update.message.reply_text(
                        text=text, parse_mode=ParseMode.HTML)
                    return

                sql.sql_update_asymmetric_expire_date(uid_hash, minute)
                config.expire_date_unit_select_dict.pop(uid_hash)
                config.command_expire_list.remove(uid_hash)
                text = '<b>Update success, please use /account command to see.</b>'
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)

            elif config.expire_date_unit_select_dict[uid_hash] == 'hour':
                try:
                    hour = int(message.text) * 60 * 60
                except Exception:
                    text = '<b>Please check your input.</b>'
                    update.message.reply_text(
                        text=text, parse_mode=ParseMode.HTML)
                    return

                sql.sql_update_asymmetric_expire_date(uid_hash, hour)
                config.expire_date_unit_select_dict.pop(uid_hash)
                config.command_expire_list.remove(uid_hash)
                text = '<b>Update success, please use /account command to see.</b>'
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)

            elif config.expire_date_unit_select_dict[uid_hash] == 'day':
                try:
                    day = int(message.text) * 60 * 60 * 24
                except Exception:
                    text = '<b>Please check your input.</b>'
                    update.message.reply_text(
                        text=text, parse_mode=ParseMode.HTML)
                    return

                sql.sql_update_asymmetric_expire_date(uid_hash, day)
                config.expire_date_unit_select_dict.pop(uid_hash)
                config.command_expire_list.remove(uid_hash)
                text = '<b>Update success, please use /account command to see.</b>'
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)

    # Do the encryption or decryption
    elif message.text:
        # First check the message whether emoji text.
        # if encrypt.detect_encrypted_emoji(message.text):
        if encrypt.detect_encrypted_emoji_c(message.text):
            # text = encrypt.convert_emoji_to_str(message.text)
            text = encrypt.convert_emoji_to_str_c(message.text)
            text = 'sencrypted[%s]' % text
            # print(text)
            symmetric_decrypt_message(
                update, context, text)

        elif encryption_mode == config.SYMMETRIC_ENCRYPTION_MODE:
            if 'sencrypted[' in message.text:
                # This is encrypted message, we need to decrypt it.
                # Fist check out the user is registerd.
                symmetric_decrypt_message(
                    update, context, message.text)

            elif 'seinline[' in message.text:

                # text = sql.sql_get_cipher_text(message.text)
                # symmetric_decrypt_message(
                #     update, context, text)
                text = '<b>Please use the inline mode to decrypted this message!</b>'
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)

            elif sql.sql_get_emoji_mode(uid_hash):
                symmetric_encrypt_message_emoji(
                    update, context, message.text)

            else:
                symmetric_encrypt_message(
                    update, context, message.text)

        elif encryption_mode == config.ASYMMETRIC_ENCRYPTION_MODE:
            if 'aencrypted[' in message.text:
                # This is encrypted message, we need to decrypt it.
                asymmetric_decrypt_message(
                    update, context, message.text)

            elif config.private_key_dict.__contains__(uid_hash):
                if config.private_key_dict[uid_hash] == 'encrypt':
                    '''For the asymmetric encryption'''
                    asymmetric_encrypt_message(
                        update, context, message.text)

                elif config.private_key_dict[uid_hash] == 'decrypt':
                    '''In here, we just sent out ciphertext to the bot,
                    now the bot still has to wait for our private key.
                    If use the symmetric key to encrypted or decrypted,
                    this step here will not need, the symmetric encryption just return the result.
                    '''
                    asymmetric_decrypt_message(
                        update, context, message.text)

                elif len(config.private_key_dict[uid_hash]) != 0:
                    asymmetric_encrypt_message(
                        update, context, message.text)

            else:
                asymmetric_encrypt_message(
                    update, context, message.text)

    elif message.photo:
        # We get the last file_id which is the biggest size.
        photo_dict = message.photo[-1]
        file_id = photo_dict['file_id']
        photo_text = 'photo[%s]' % file_id
        if encryption_mode == config.SYMMETRIC_ENCRYPTION_MODE:
            symmetric_encrypt_message(
                update, context, photo_text)

        elif encryption_mode == config.ASYMMETRIC_ENCRYPTION_MODE:
            asymmetric_encrypt_message(
                update, context, photo_text)


@run_async
def process_message(update, context):

    if not update.message:
        return

    if update.message.chat.type == 'private':
        process_message_private(update, context)

    elif update.message.chat.type == 'supergroup':
        return
