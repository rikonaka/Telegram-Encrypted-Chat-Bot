#!/usr/bin/env python3

from encryptedchatbot import constants

from telegram import ReplyKeyboardMarkup
from telegram import InlineKeyboardMarkup
from telegram import InlineKeyboardButton


def github_link():
    button0 = InlineKeyboardButton(
        text='Manual',
        url='https://github.com/rikonaka/Telegram-Encrypted-Chat-Bot/wiki/Manual'
    )
    button1 = InlineKeyboardButton(
        text='Github Repositories',
        url='https://github.com/rikonaka/Telegram-Encrypted-Chat-Bot'
    )
    buttons_list = [[button0, button1]]
    keyboard = InlineKeyboardMarkup(buttons_list)
    return keyboard


def inline_keyboard(switch_inline_query_str):

    bot_link = 'https://t.me/{}'.format(constants.GET_ME.username)
    # button0 = InlineKeyboardButton(text='Private chat', url=bot_link)
    button0 = InlineKeyboardButton(text='Bot', url=bot_link)

    button1 = InlineKeyboardButton(
        text='Preview', switch_inline_query_current_chat=switch_inline_query_str)
    # button2 = InlineKeyboardButton(
    #     text='Clear Preview', switch_inline_query_current_chat='')
    buttons_list = [[button0, button1]]
    # buttons_list = [[button0, button1, button2]]
    keyboard = InlineKeyboardMarkup(buttons_list)
    return keyboard


def inline_chtm_keyboard():

    buttonu = InlineKeyboardButton(text='unlimited', callback_data='chtm-u')
    button1 = InlineKeyboardButton(text='1', callback_data='chtm-1')
    button2 = InlineKeyboardButton(text='2', callback_data='chtm-2')
    button3 = InlineKeyboardButton(text='3', callback_data='chtm-3')
    button5 = InlineKeyboardButton(text='5', callback_data='chtm-5')
    button8 = InlineKeyboardButton(text='8', callback_data='chtm-8')
    # button2 = InlineKeyboardButton(
    #     text='Clear Preview', switch_inline_query_current_chat='')
    buttons_list = [[buttonu, button1, button2], [button3, button5, button8]]
    # buttons_list = [[button0, button1, button2]]
    keyboard = InlineKeyboardMarkup(buttons_list)
    return keyboard


def config_keyboard():
    '''Show the config keyboard
    '''
    button = [['/symmetric', '/asymmetric', '/chep', '/chtm'],
              ['/emoji', '/destroy']]
    keyboard = ReplyKeyboardMarkup(button, one_time_keyboard=True)
    return keyboard


def admin_keyboard():
    '''Show the administrator's manager keyboard.
    '''
    button = [['/status', '/mainten', '/restart', '/truncate'],
              ['/register', '/account', '/keygen'],
              ['/config', '/help']]
    # keyboard = ReplyKeyboardMarkup(button, one_time_keyboard=True)
    # Not use the one_time_keyboard option here for administrator.
    keyboard = ReplyKeyboardMarkup(button)
    return keyboard


def user_keyboard():
    button = [['/register', '/account', '/keygen'],
              ['/config', '/help']]
    keyboard = ReplyKeyboardMarkup(button, one_time_keyboard=True)
    return keyboard


def expiredate_unit_selection_keyboard():
    button = [['/second', '/minute'], ['/hour', '/day']]
    keyboard = ReplyKeyboardMarkup(button, one_time_keyboard=True)
    return keyboard
