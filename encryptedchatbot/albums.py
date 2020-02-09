#!/usr/bin/env python3

import datetime

from telegram import InputMedia, InputMediaPhoto, InputMediaVideo
from telegram.ext import DispatcherHandlerStop
from telegram import ChatAction
from telegram import ParseMode
from telegram.ext.dispatcher import run_async

from encryptedchatbot import config
from encryptedchatbot.utils import check_admin
from encryptedchatbot import sql
from encryptedchatbot.utils import only_admin


@run_async
def CollectAlbum_Private(update, context):
    pass


@run_async
def CollectAlbum_Group(update, context):
    pass


@run_async
def collect_album(update, context):
    '''
    if the media_group_id not a key in the dictionary yet:
        - send sending action
        - create a key in the dict with media_group_id
        - add a list to the key and the first element is this update
        - schedule a job in 1 sec
    else:
        - add update to the list of that media_group_id
    '''
    # now we append every file_id into list and sql

    if update.message:
        if update.message.chat.type == 'private':
            CollectAlbum_Private(update, context)
        elif update.message.chat.type == 'supergroup':
            CollectAlbum_Group(update, context)
    else:
        return
