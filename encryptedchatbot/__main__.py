#!/usr/bin/env python3

import logging
from threading import Thread
from datetime import datetime
import sys
import os
import time

from encryptedchatbot import config
from encryptedchatbot import commands
from encryptedchatbot import messages
from encryptedchatbot import utils
from encryptedchatbot import albums
from encryptedchatbot import custom_filters
from encryptedchatbot import version
from encryptedchatbot.utils import only_admin

from telegram.ext import Updater
from telegram.ext import Filters
from telegram.ext import MessageHandler
from telegram.ext import CommandHandler
from telegram.ext import InlineQueryHandler
from telegram.ext import CallbackQueryHandler

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)
logger = logging.getLogger(__name__)


def error_callback(update, context, error):

    dt = datetime.now()
    date = dt.strftime('%Y-%m-%d %I:%M:%S')
    log_str = '%s: update %s caused error %s' % (date, update, error)
    logger.warning(log_str)

    with open(config.ERROR_LOG, 'a+') as fp:
        fp.writelines('%s\n' % log_str)


def main():

    current_version = version.bot_version()
    running_message = 'encryptedchatbot: v%s\nrunning...' % current_version
    print(running_message)
    config.bot_start_time = time.time()

    # define the updater
    updater = Updater(token=config.BOT_TOKEN, use_context=True)
    # define the dispatcher
    dp = updater.dispatcher

    def stop_and_restart():
        '''Gracefully stop the updater and replace the current process with a new one'''
        updater.stop()
        os.execl(sys.executable, sys.executable, *sys.argv)

    @only_admin
    def restart(update, context):
        update.message.reply_text('Bot is restarting...')
        Thread(target=stop_and_restart).start()

    '''Define the jobs that are executed regularly.'''
    # define jobs
    job = updater.job_queue

    job.run_once(commands.job_check_database, when=1)
    # check the expire data every 1 min.
    job.run_repeating(
        commands.job_check_expire_date, interval=60, first=0)
    job.run_repeating(
        commands.job_command_expire, interval=600, first=0)

    '''Define the commands that only the administrator can execute.'''
    # albums
    dp.add_handler(MessageHandler(custom_filters.album,
                                  albums.collect_album, pass_job_queue=True), 1)
    # messages
    dp.add_handler(MessageHandler(
        Filters.all, messages.process_message), 1)

    # admin command: show the program status.
    dp.add_handler(CommandHandler('status', commands.command_status), 2)
    # admin command: turn on or turn off maintenance mode.
    dp.add_handler(CommandHandler('mainten',
                                  commands.command_maintenance), 2)
    # admin command: restart the program.
    dp.add_handler(CommandHandler('restart', restart), 2)
    dp.add_handler(CommandHandler('truncate', commands.command_truncate), 2)

    '''Define the commands that the everyone can execute.'''
    dp.add_handler(CommandHandler('start', commands.command_start), 2)
    dp.add_handler(CommandHandler('register', commands.command_register), 2)
    dp.add_handler(CommandHandler('account', commands.command_account), 2)
    dp.add_handler(CommandHandler('keygen', commands.command_keygen), 2)
    dp.add_handler(CommandHandler('config', commands.command_config), 2)
    dp.add_handler(CommandHandler(
        'symmetric', commands.command_symmetric_encryption), 2)
    dp.add_handler(CommandHandler(
        'asymmetric', commands.command_asymmetric_encryption), 2)
    dp.add_handler(CommandHandler('help', commands.command_help), 2)
    dp.add_handler(CommandHandler('emoji', commands.command_emoji), 2)
    dp.add_handler(CommandHandler('destroy', commands.command_destroy), 2)
    dp.add_handler(CommandHandler('chep',
                                  commands.command_change_expire_date), 2)
    dp.add_handler(CommandHandler('chtm',
                                  commands.command_change_time_to_live), 2)
    dp.add_handler(CommandHandler('second',
                                  commands.command_second), 2)
    dp.add_handler(CommandHandler('minute',
                                  commands.command_minute), 2)
    dp.add_handler(CommandHandler('hour',
                                  commands.command_hour), 2)
    dp.add_handler(CommandHandler('day',
                                  commands.command_day), 2)
    dp.add_handler(MessageHandler(Filters.command, utils.invalid_command), 2)

    '''Add inline query handle.'''
    dp.add_handler(InlineQueryHandler(commands.command_inline))

    '''Add inline keyboard query'''
    dp.add_handler(CallbackQueryHandler(commands.command_query_back))

    # handle errors
    dp.add_error_handler(error_callback)
    updater.start_polling()
    updater.idle()


if __name__ == '__main__':
    main()
