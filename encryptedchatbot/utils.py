#!/usr/bin/env python3

from functools import wraps
from encryptedchatbot import config

from telegram.ext.dispatcher import run_async
from telegram import InlineQueryResultArticle
from telegram import InputTextMessageContent
from telegram import ParseMode

import uuid


def check_admin(uid_hash):
    '''Check the user which sent this message is admin or not.

    Args:
        uid_hash(str): get it from update.message.from_user.id.

    Returns:
        False: means that the user is not administrator.
        True: contrary to the above.
    '''
    if uid_hash not in config.ADMINS:
        return False
    else:
        return True


def invalid_command(update, context):
    if update.message:
        text = '<b>This command is invalid or can only be used in private chat.</b>'
        # update.message.reply_text(text=text, quote=True, parse_mode=ParseMode.HTML)
        update.message.reply_text(text=text, parse_mode=ParseMode.HTML)


def maintenance_now(update, context):
    if update.message:
        update.message.reply_text(
            text=config.MAINTENANCE_EXPRESSION, parse_mode=ParseMode.HTML)


def only_admin(func):
    @wraps(func)
    def wrapped(update, context, *args, **kwargs):
        if str(update.message.from_user.id) not in config.ADMINS:
            invalid_command(update, context, *args, **kwargs)
            return
        else:
            # admin will run the command.
            return func(update, context, *args, **kwargs)
    return wrapped


def only_private_chat(func):
    @wraps(func)
    def wrapped(update, context, *args, **kwargs):
        if update.message.chat.type == 'supergroup':
            invalid_command(update, context, *args, **kwargs)
            return
        elif update.message.chat.type == 'private':
            # private chat will run the command.
            return func(update, context, *args, **kwargs)
        else:
            return
    return wrapped


def is_maintenance(func):
    @wraps(func)
    def wrapped(update, context, *args, **kwargs):
        if config.maintenance_mode:
            # The server is under maintenance.
            maintenance_now(update, context)
            return
        else:
            return func(update, context, *args, **kwargs)
    return wrapped


def main():
    '''Put main() funtion here for test'''
    return
