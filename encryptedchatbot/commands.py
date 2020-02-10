#!/usr/bin/env python3

import copy
import random
import time
from datetime import datetime
from datetime import timedelta
import uuid

from encryptedchatbot.utils import only_admin
from encryptedchatbot.utils import only_private_chat
from encryptedchatbot.utils import is_maintenance
from encryptedchatbot.utils import check_admin
from encryptedchatbot.utils import check_string
from encryptedchatbot import keyboards
from encryptedchatbot import messages
from encryptedchatbot import utils
from encryptedchatbot import config
from encryptedchatbot import sql
from encryptedchatbot import encrypt
from encryptedchatbot import version

# from telegram import MessageEntity
from telegram import ParseMode
from telegram import InlineQueryResultArticle
from telegram import InputTextMessageContent
# from telegram import constants as t_consts
from telegram.ext.dispatcher import run_async
from telegram import TelegramError

'''Job.'''


@run_async
def job_check_database(context, *args, **kwargs):
    '''Check if the table in the databse is normal.
    If not, make it normal.
    Check table list:
        e_user_x
        e_key_x
        e_history_x
        e_config_x
        e_nonce_x
        e_public_key_x
    '''

    sql.sql_check_database()


@run_async
def job_check_expire_date(context):
    '''Check the key expire data, if expired, delete the key from database.
    '''
    secret_key_hash_list = sql.sql_check_secret_key_expired_job()
    if secret_key_hash_list:
        sql.sql_delete_expired_secret_key(secret_key_hash_list)

    uid_hash_list = sql.sql_check_public_key_expired_job()
    if uid_hash_list:
        sql.sql_update_expired_public_key(uid_hash_list, 64 * '0')

    nonce_hash_list = sql.sql_check_nonce_expired_job()
    if nonce_hash_list:
        sql.sql_delete_expired_nonce(nonce_hash_list)

    cipher_text_hash_list = sql.sql_check_cipher_text_expired_job()
    if cipher_text_hash_list:
        sql.sql_delete_expired_cipher_text(cipher_text_hash_list)


@run_async
def job_command_expire(context):
    '''Automatically let user input command expire.
    '''
    if len(config.command_expire_list) > 0:
        uid_hash = config.command_expire_list.pop(0)
        if config.keygen_confirm_dict.__contains__(uid_hash):
            config.keygen_confirm_dict.pop(uid_hash)
        if config.expire_date_unit_select_dict.__contains__(uid_hash):
            config.expire_date_unit_select_dict.pop(uid_hash)
        if config.private_key_dict.__contains__(uid_hash):
            config.private_key_dict.pop(uid_hash)
        if config.public_key_dict.__contains__(uid_hash):
            config.public_key_dict.pop(uid_hash)


'''Admin command.'''


@run_async
@only_admin
@only_private_chat
def command_status(update, context):

    # keyboard = keyboards.github_link_kb()
    keyboard = keyboards.admin_keyboard()

    sql_status_list = sql.sql_status()
    sql_status_str = str()
    if len(sql_status_list) != 0:
        for s in sql_status_list:
            sql_status_str = '%s%s: %s\n' % (
                sql_status_str, s['table_name'], s['rows'])
    else:
        sql_status_str = 'get_sql_status_error'

    text = (
        '<b>Bot Status:</b>\n\n'
        '<b>mysql status:</b>\n'
        '%s\n'
        '<b>maintenance:</b>\n'
        '%s' % (str(sql_status_str),
                str(config.maintenance_mode))
    )
    update.message.reply_text(
        text=text, parse_mode=ParseMode.HTML, reply_markup=keyboard)


@run_async
@only_admin
@only_private_chat
def command_maintenance(update, context):

    if config.maintenance_mode == False:
        config.maintenance_mode = True
        text = '<b>Maintenance mode enabled</b>'
        update.message.reply_text(text=text, parse_mode=ParseMode.HTML)

    elif config.maintenance_mode == True:
        config.maintenance_mode = False
        text = '<b>Maintenance mode disabled</b>'
        update.message.reply_text(text=text, parse_mode=ParseMode.HTML)


@run_async
@only_admin
@only_private_chat
def command_truncate(update, context):
    '''As you see.'''
    sql.sql_truncate_all_table()


@run_async
def command_inline(update, context):
    '''Process the message from inline query'''
    # type(text) is str.
    text = update.inline_query.query
    text = text.strip()
    if len(text) == 0:
        return 0

    uuid_me = uuid.uuid4()
    results = list()
    uid = update.inline_query.from_user.id
    uid_hash = encrypt.blake2b_hash(str(uid))

    if config.maintenance_mode:
        results.append(InlineQueryResultArticle(id=uuid_me, title=config.SERVER_ERROR_EXPRESSION, description=config.MAINTENANCE_EXPRESSION,
                                                input_message_content=InputTextMessageContent(config.MAINTENANCE_EXPRESSION, parse_mode=ParseMode.HTML)))
        try:
            update.inline_query.answer(
                results, cache_time=60, is_personal=True)
        except Exception:
            pass
        return 0

    if sql.sql_check_user(uid_hash) != 1:
        plain_text = 'Sorry, we can\'t decrypt this ciphertext'
        results.append(InlineQueryResultArticle(id=uuid_me, title=config.SERVER_ERROR_EXPRESSION, description=plain_text,
                                                input_message_content=InputTextMessageContent(config.SERVER_ERROR_EXPRESSION, parse_mode=ParseMode.HTML)))
        try:
            update.inline_query.answer(
                results, cache_time=60, is_personal=True)
        except Exception:
            pass
        return 0

    if 'seinline[' in text:
        try:
            cipher_text_hash = text.split('seinline')[1][1:-1]
        except IndexError:
            return -1

        if len(cipher_text_hash) == 0 or not check_string(cipher_text_hash):
            return -1

        # Check the cipher_text.
        cipher_text = sql.sql_get_cipher_text(cipher_text_hash)
        # print('commands(cipher_text): ' + cipher_text)
        if not cipher_text:
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

            results.append(InlineQueryResultArticle(id=uuid_me, title=config.EXPIRE_ERROR_EXPRESSION, description='please check your input',
                                                    input_message_content=InputTextMessageContent(config.SERVER_ERROR_EXPRESSION, parse_mode=ParseMode.HTML)))
            try:
                update.inline_query.answer(
                    results, cache_time=60, is_personal=True)
            except Exception:
                pass
            return -1

        # Check the plain_text.
        plain_text = messages.symmetric_decrypt_inline(
            update, context, uid_hash, cipher_text)
        # print('commands(plain_text): ' + plain_text)
        if not plain_text:
            results.append(InlineQueryResultArticle(id=uuid_me, title=config.SERVER_ERROR_EXPRESSION, description='please check your input',
                                                    input_message_content=InputTextMessageContent(config.SERVER_ERROR_EXPRESSION, parse_mode=ParseMode.HTML)))
            try:
                update.inline_query.answer(
                    results, cache_time=60, is_personal=True)
            except Exception:
                pass
            return -1

        results.append(InlineQueryResultArticle(id=uuid_me, title='De-Result', description=plain_text,
                                                input_message_content=InputTextMessageContent(plain_text, parse_mode=ParseMode.HTML)))
        try:
            update.inline_query.answer(
                results, cache_time=60, is_personal=True)
        except Exception:
            pass

    else:
        cipher_text = messages.symmetric_encrypt_inline(
            update, context, uid_hash, text)
        cipher_text_hash = encrypt.sha256_hash(cipher_text)
        if not cipher_text or cipher_text == -1 or not cipher_text_hash:
            results.append(InlineQueryResultArticle(id=uuid_me, title=config.SERVER_ERROR_EXPRESSION, description='please check your input',
                                                    input_message_content=InputTextMessageContent(config.SERVER_ERROR_EXPRESSION, parse_mode=ParseMode.HTML)))
            try:
                update.inline_query.answer(
                    results, cache_time=60, is_personal=True)
            except Exception:
                pass

            return -1

        switch_inline_query_str = 'seinline[%s]' % cipher_text_hash
        keyboard = keyboards.inline_keyboard(switch_inline_query_str)
        sql.sql_insert_cipher_text(uid_hash, cipher_text_hash, cipher_text)

        # Disable the sql_get_emoji_mode in the inline mode.
        # if 1 == 2:
        if sql.sql_get_emoji_mode(uid_hash):
            # if user want to use the emoji encrption.
            try:
                cipher_data = cipher_text.split('sencrypted')[1][1:-1]
                # print(cipher_text)
            except IndexError:
                return -1

            if len(cipher_data) == 0 or not check_string(cipher_data):
                return -1

            emoji_text = encrypt.convert_str_to_emoji_c(cipher_data)
            # print(emoji_text)
            # emoji_text = 'sencrypted[%s]' % emoji_text
            results.append(InlineQueryResultArticle(id=uuid_me, title='En-Result', description='id: %s' % str(uuid_me)[0:8],
                                                    input_message_content=InputTextMessageContent(emoji_text, parse_mode=ParseMode.HTML), reply_markup=keyboard))
            try:
                update.inline_query.answer(
                    results, cache_time=60, is_personal=True)
            except Exception:
                pass
        else:
            results.append(InlineQueryResultArticle(id=uuid_me, title='En-Result', description='id: %s' % str(uuid_me)[0:8],
                                                    input_message_content=InputTextMessageContent(cipher_text, parse_mode=ParseMode.HTML), reply_markup=keyboard))
            try:
                update.inline_query.answer(
                    results, cache_time=60, is_personal=True)
            except Exception:
                pass


def command_query_back_chtm(update, context, uid_hash, update_vaule):
    '''Change the user's remain decryption time as ulimited.

    Args:
        bot(Telegram bot type).
        update(Telegram update type).
        uid_hash(str).
        update_value(int).
    '''
    if sql.sql_update_remaining_decryption_time_config(uid_hash, update_vaule) == -1:
        return

    date = datetime.fromtimestamp(int(time.time()))
    try:
        context.bot.edit_message_text(
            message_id=update.callback_query.message.message_id,
            chat_id=update.callback_query.message.chat.id,
            text='<b>[%s]</b> Now use the maximum number of decryptions is <b>%d</b>. %s' % (
                date, update_vaule, config.GOOD_EXPRESSION),
            parse_mode=ParseMode.HTML,
            reply_markup=keyboards.inline_chtm_keyboard()
        )
    except Exception:
        pass

    '''
    try:
        bot.send_message(chat_id=update.callback_query.message.chat.id,
                         text='Now use the maximum number of decryptions is %d. %s' % (
                             update_vaule, config.GOOD_EXPRESSION),
                         parse_mode=ParseMode.HTML,
                         reply_markup=keyboards.inline_chtm_keyboard()
                         )
    except Exception:
        # print(e)
        pass
    '''

    return


@run_async
@is_maintenance
def command_query_back(update, context):

    # print(dir(update))
    # print(update.edited_message)
    # print(update.effective_message)
    # print(dir(update.callback_query))
    # print(update.callback_query)
    # print(update.callback_query.message)
    # print(dir(update.callback_query.edit_message_text))
    uid = update.callback_query.from_user.id
    uid_hash = encrypt.blake2b_hash(str(uid))
    if update.callback_query.data:
        query = update.callback_query.data
        # print(query)
    else:
        return

    if query == 'chtm-u':
        command_query_back_chtm(update, context, uid_hash,
                                config.DEFAULT_MAX_DECRYPTION_TIME)

    elif query == 'chtm-1':
        command_query_back_chtm(update, context, uid_hash, 1)

    elif query == 'chtm-2':
        command_query_back_chtm(update, context, uid_hash, 2)

    elif query == 'chtm-3':
        command_query_back_chtm(update, context, uid_hash, 3)

    elif query == 'chtm-5':
        command_query_back_chtm(update, context, uid_hash, 5)

    elif query == 'chtm-8':
        command_query_back_chtm(update, context, uid_hash, 8)

    return


'''User command.'''


@run_async
@is_maintenance
def command_help(update, context):

    keyboard = keyboards.github_link()
    start_time = config.bot_start_time
    end_time = time.time()
    text = (
        '<b>In order to avoid the chat record in the telegram group '
        'being used for the testimony, the message encryption bot @encrypted_chat_bot (v%s) was developed.</b>'
        '\n\n'
        'Notes: if you want to use inline mode, make sure the string you want to encrypt is less than <b>256</b> bytes.'
        '\n\n'
        'Uptime: %s'
    ) % (version.bot_version(), str(timedelta(seconds=int(end_time - start_time))))
    update.message.reply_text(
        text=text, parse_mode=ParseMode.HTML, reply_markup=keyboard)

    text = '<b>Hi, what can I do for you? %s</b>' % config.CALM_EXPRESSION

    if update.message.chat.type == 'private':
        keyboard = keyboards.user_keyboard()
        update.message.reply_text(
            text=text, parse_mode=ParseMode.HTML, reply_markup=keyboard)


@run_async
@only_private_chat
@is_maintenance
def command_start(update, context):
    '''For the first time use.
    '''
    keyboard = keyboards.user_keyboard()

    text = (
        'This bot comes from a <b>NGO</b>. '
        'In order to support the anti-authoritarian legal battles around the world, we developed this bot. '
        'This bot can help us encrypt the chat history in the group and periodically clear the chat history.'
    )
    update.message.reply_text(
        text=text, parse_mode=ParseMode.HTML, reply_markup=keyboard)


@run_async
@only_private_chat
@is_maintenance
def command_register(update, context):
    '''For new user.
    '''
    uid = update.message.from_user.id
    text = (
        'We got your user id to be this:\n<b>%d</b>\n'
        'This will be your only username in the system.'
    ) % uid
    update.message.reply_text(text=text, parse_mode=ParseMode.HTML)
    '''The process_dict should contain these thing.
    private_key will not store in the database.
    {
        'uid_hash', ...(64B hex string),
        'public_key': ...(64B hex string),
        'create_time': ...(int)
    }
    '''
    asymmetric_key_dict = encrypt.asymmetric_key_generate()
    private_key_bytes = asymmetric_key_dict['private_key']
    public_key_bytes = asymmetric_key_dict['public_key']

    private_key_hex_str = encrypt.convert_bytes_to_str(private_key_bytes)
    public_key_hex_str = encrypt.convert_bytes_to_str(public_key_bytes)

    process_dict = dict()
    process_dict['uid_hash'] = encrypt.blake2b_hash(str(uid))
    process_dict['public_key'] = public_key_hex_str
    # Use the timestamp(int).
    process_dict['create_time'] = int(time.time())

    status = sql.sql_register(process_dict)
    if status == -1:
        text = '<b>Register failed, please contact your administrator! %s</b>' % config.SURPRISED_EXPRESSION
        update.message.reply_text(text=text, parse_mode=ParseMode.HTML)
        return

    elif status == 1:
        text = '<b>You have already registered, please do not register again! %s</b>' % config.NO_EXPRESSION
        update.message.reply_text(text=text, parse_mode=ParseMode.HTML)
        return

    else:
        text = '<b>Register success! %s</b>' % config.GOOD_EXPRESSION
        update.message.reply_text(text=text, parse_mode=ParseMode.HTML)
        # We show the private_key to user, not store in the server.
        text = (
            'Please keep this <b>asymmetric private key</b> in a safe place, don\'t let it leak to others. %s'
            'We won\'t store this key on the server. If you lose the key or regenerate a new key and replace it, the message encrypted with this key will be permanently lost.'
        ) % config.GOOD_EXPRESSION
        update.message.reply_text(text=text,
                                  parse_mode=ParseMode.HTML)
        text = '<b>%s</b>' % private_key_hex_str
        update.message.reply_text(text=text, parse_mode=ParseMode.HTML)


@run_async
@only_private_chat
@is_maintenance
def command_account(update, context):
    '''Show the account details for user.
    '''
    uid = update.message.from_user.id
    uid_hash = encrypt.blake2b_hash(str(uid))
    if sql.sql_check_user(uid_hash) != 1:
        re_text = "<b>Please register first!</b>"
        update.message.reply_text(text=re_text, parse_mode=ParseMode.HTML)
        return

    expire_data_dict = sql.sql_get_all_expire_date(uid_hash)
    date_s = str(timedelta(seconds=int(expire_data_dict['sexpire_date'])))
    date_a = datetime.fromtimestamp(
        int(sql.sql_get_public_key_expire_date_from_public_key(uid_hash)))
    date_aa = str(timedelta(seconds=int(expire_data_dict['aexpire_date'])))
    date_n = datetime.fromtimestamp(int(time.time()))

    encryption_mode = sql.sql_get_encryption_mode(uid_hash)

    if encryption_mode == config.SYMMETRIC_ENCRYPTION_MODE:
        encryption_mode = 'Symmetric'
    elif encryption_mode == config.ASYMMETRIC_ENCRYPTION_MODE:
        encryption_mode = 'Asymmetric'

    uid_text = 'UID: <b>%d</b>\nEncryption mode: <b>%s</b>\nUTC time now: <b>%s</b>' % (
        uid, encryption_mode, date_n)
    update.message.reply_text(text=uid_text, parse_mode=ParseMode.HTML)

    symmetirc_text = 'Each symmetric secret key expire interval (UTC): <b>%s</b>' % (
        date_s)
    update.message.reply_text(text=symmetirc_text,
                              parse_mode=ParseMode.HTML)

    asymmetric_text = (
        'Asymmetric public key (Note: we will not save the private key): <b>%s</b>\nExpire date (UTC): <b>%s</b>\n'
        'Each asymmetric public key expire interval (UTC): <b>%s</b>\n'
        'If your public key become 0, that mean your public key is expired, you need to re-gen new key.'
    ) % (sql.sql_get_public_key(uid_hash), date_a, date_aa)
    update.message.reply_text(text=asymmetric_text,
                              parse_mode=ParseMode.HTML)


@run_async
@only_private_chat
@is_maintenance
def command_keygen(update, context):
    '''Generate the new key for user.
    '''

    uid = update.message.from_user.id
    uid_hash = encrypt.blake2b_hash(str(uid))
    if sql._sql_check_uid(uid_hash) != 1:
        return

    uid_hash_list = list()
    uid_hash_list.append(uid_hash)

    if config.keygen_confirm_dict.__contains__(uid_hash):
        if config.keygen_confirm_dict[uid_hash] == False:
            config.keygen_confirm_dict[uid_hash] = True
            config.keygen_confirm_dict.pop(uid_hash)
            config.command_expire_list.remove(uid_hash)

            asymmetric_key_dict = encrypt.asymmetric_key_generate()
            private_key_hex = encrypt.convert_bytes_to_str(
                asymmetric_key_dict['private_key'])
            public_key_hex = encrypt.convert_bytes_to_str(
                asymmetric_key_dict['public_key'])

            if sql.sql_update_expired_public_key(uid_hash_list, public_key_hex) == -1:
                text = 'Update asymmetric key failed.'
                update.message.reply_text(
                    text=text, parse_mode=ParseMode.HTML)
                return

            text = (
                'Generate success, this is your new <b>Asymmetric Secret Key</b>. %s'
                'The database will be updated automatically. '
                'Similarly, we will not store this key, so please keep it safe.'
            ) % (config.GOOD_EXPRESSION)
            update.message.reply_text(text=text, parse_mode=ParseMode.HTML)
            text = '<b>%s</b>' % private_key_hex
            update.message.reply_text(text=text, parse_mode=ParseMode.HTML)
    else:
        text = (
            'Please confirm if you need to really regenerate <b>Asymmetric Key</b>. '
            'If you regenerate the key, the old chat message no longer supports decryption reading.'
            'But we also <b>recommend</b> that you reset this key periodically to avoid exhaustive attacks.'
            'After all, there are quantum computers now.'
            'If you confirm to regenerate this key, click /keygen button <b>again</b>.'
        )
        # False mean that the program will waiting for the user confirmation.
        config.keygen_confirm_dict[uid_hash] = False
        config.command_expire_list.append(uid_hash)
        update.message.reply_text(
            text=text, parse_mode=ParseMode.HTML)


@run_async
@only_private_chat
@is_maintenance
def command_config(update, context):
    '''Show the config keyboard.
    '''

    if update.message.chat.type == 'private':
        keyboard = keyboards.config_keyboard()
        text = '<b>This is config menu.</b> %s' % config.NO_EXPRESSION
        update.message.reply_text(
            text=text, parse_mode=ParseMode.HTML, reply_markup=keyboard)


@run_async
@only_private_chat
@is_maintenance
def command_symmetric_encryption(update, context):
    '''Switching encryption method'''

    uid_hash = encrypt.blake2b_hash(str(update.message.from_user.id))
    sql.sql_update_encryption_mode(uid_hash, config.SYMMETRIC_ENCRYPTION_MODE)
    text = 'Start using symmetric encryption now. %s' % config.CALM_EXPRESSION
    update.message.reply_text(text=text, parse_mode=ParseMode.HTML)


@run_async
@only_private_chat
@is_maintenance
def command_asymmetric_encryption(update, context):
    '''Switching encryption method'''
    uid_hash = encrypt.blake2b_hash(str(update.message.from_user.id))
    sql.sql_update_encryption_mode(uid_hash, config.ASYMMETRIC_ENCRYPTION_MODE)
    text = 'Start using asymmetric encryption now. %s' % config.CALM_EXPRESSION
    update.message.reply_text(text=text, parse_mode=ParseMode.HTML)


@run_async
@only_private_chat
@is_maintenance
def command_emoji(update, context):
    '''Enable the emoji encryption.
    '''

    uid = update.message.from_user.id
    uid_hash = encrypt.blake2b_hash(str(uid))

    emoji_mode = sql.sql_get_emoji_mode(uid_hash)
    if emoji_mode == 0:
        text = 'Start using emoji encryption now. %s' % config.CALM_EXPRESSION
        new_emoji_mode = 1
    elif emoji_mode == 1:
        text = 'Stop using emoji encryption now. %s' % config.CALM_EXPRESSION
        new_emoji_mode = 0
    else:
        text = config.SERVER_ERROR_EXPRESSION
        update.message.reply_text(text=text, parse_mode=ParseMode.HTML)
        return

    if sql.sql_update_emoji_mode(uid_hash, new_emoji_mode):
        text = config.SERVER_ERROR_EXPRESSION

    update.message.reply_text(text=text, parse_mode=ParseMode.HTML)


@run_async
@only_private_chat
@is_maintenance
def command_destroy(update, context):
    '''Delete all the user's key'''
    uid_hash = encrypt.blake2b_hash(str(update.message.from_user.id))
    sql_status = sql.sql_delete_user_all_key(uid_hash)
    if sql_status != 0:
        text = '<b>There are some problems when deleting, but the problem is not big.</b>'
    else:
        text = '<b>Finish!</b>'

    update.message.reply_text(text=text, parse_mode=ParseMode.HTML)


@run_async
@only_private_chat
@is_maintenance
def command_change_expire_date(update, context):
    '''Set the symmetric secret key expire date'''
    uid_hash = encrypt.blake2b_hash(str(update.message.from_user.id))
    if sql.sql_check_user(uid_hash) != 1:
        return

    keyboard = keyboards.expiredate_unit_selection_keyboard()

    encryption_mode = sql.sql_get_encryption_mode(uid_hash)
    if encryption_mode == config.SYMMETRIC_ENCRYPTION_MODE:
        expire_time = sql.sql_get_secret_key_expire_date_from_config(uid_hash)
        text = 'Change the (default is %s) <b>symmetric encryption</b> expired time.' % (
            str(timedelta(seconds=int(expire_time))))
    elif encryption_mode == config.ASYMMETRIC_ENCRYPTION_MODE:
        expire_time = sql.sql_get_public_key_expire_date_from_config(uid_hash)
        text = 'Change the (default is %s) <b>asymmetric encryption</b> expired time.' % (
            str(timedelta(seconds=int(expire_time))))

    update.message.reply_text(
        text=text, parse_mode=ParseMode.HTML, reply_markup=keyboard)
    now_time = datetime.fromtimestamp(int(time.time()))
    text = '<b>Please select the unit you want to set the time for (now time is: %s):</b>' % now_time
    update.message.reply_text(
        text=text, parse_mode=ParseMode.HTML, reply_markup=keyboard)


@run_async
@only_private_chat
@is_maintenance
def command_change_time_to_live(update, context):
    uid_hash = encrypt.blake2b_hash(str(update.message.from_user.id))
    if sql.sql_check_user(uid_hash) != 1:
        return

    keyboard = keyboards.inline_chtm_keyboard()
    text = 'Please choose the message decryption time to live value.'
    update.message.reply_text(
        text=text, parse_mode=ParseMode.HTML, reply_markup=keyboard)


@run_async
@only_private_chat
@is_maintenance
def command_second(update, context):
    uid_hash = encrypt.blake2b_hash(str(update.message.from_user.id))
    if sql._sql_check_uid(uid_hash) != 1:
        return
    config.expire_date_unit_select_dict[uid_hash] = 'second'
    config.command_expire_list.append(uid_hash)
    text = 'How long does it take to expire (<b>second</b>)?'
    update.message.reply_text(
        text=text, parse_mode=ParseMode.HTML)


@run_async
@only_private_chat
@is_maintenance
def command_minute(update, context):
    uid_hash = encrypt.blake2b_hash(str(update.message.from_user.id))
    if sql._sql_check_uid(uid_hash) != 1:
        return
    config.expire_date_unit_select_dict[uid_hash] = 'minute'
    config.command_expire_list.append(uid_hash)
    text = 'How long does it take to expire (<b>minute</b>)?'
    update.message.reply_text(
        text=text, parse_mode=ParseMode.HTML)


@run_async
@only_private_chat
@is_maintenance
def command_hour(update, context):
    uid_hash = encrypt.blake2b_hash(str(update.message.from_user.id))
    if sql._sql_check_uid(uid_hash) != 1:
        return
    config.expire_date_unit_select_dict[uid_hash] = 'hour'
    config.command_expire_list.append(uid_hash)
    text = 'How long does it take to expire (<b>hour</b>)?'
    update.message.reply_text(
        text=text, parse_mode=ParseMode.HTML)


@run_async
@only_private_chat
@is_maintenance
def command_day(update, context):
    uid_hash = encrypt.blake2b_hash(str(update.message.from_user.id))
    if sql._sql_check_uid(uid_hash) != 1:
        return
    config.expire_date_unit_select_dict[uid_hash] = 'day'
    config.command_expire_list.append(uid_hash)
    text = 'How long does it take to expire (<b>day</b>)?'
    update.message.reply_text(
        text=text, parse_mode=ParseMode.HTML)
