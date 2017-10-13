#!/usr/bin/python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
import configargparse
import json

logging.basicConfig(
    format='[%(name)10.10s][%(levelname)8.8s] %(message)s',
    level=logging.INFO
)
log = logging.getLogger('utils')


def get_path(path):
    if not os.path.isabs(path):
        path = os.path.join(os.path.dirname(__file__), path)
    return path


def get_args():
    if '-cf' not in sys.argv and '--config' not in sys.argv:
        config_files = [get_path('config/config.ini')]
    parser = configargparse.ArgParser(default_config_files=config_files)
    parser.add_argument(
        '-cf', '--config',
        is_config_file=True,
        help='Configuration file'
    )
    parser.add_argument(
        '-ocid', '--OAUTH2_CLIENT_ID',
        type=str,
        required=True
    )
    parser.add_argument(
        '-ocs', '--OAUTH2_CLIENT_SECRET',
        type=str,
        required=True
    )
    parser.add_argument(
        '-oru', '--OAUTH2_REDIRECT_URI',
        type=str,
        required=True
    )
    parser.add_argument(
        '-ssk', '--STRIPE_SECRET_KEY',
        type=str,
        required=True
    )
    parser.add_argument(
        '-spk', '--STRIPE_PUBLISHABLE_KEY',
        type=str,
        required=True
    )
    parser.add_argument(
        '-swk', '--STRIPE_WEBHOOK_KEY',
        type=str,
        required=True
    )
    parser.add_argument(
        '-token', '--bot_tokens',
        type=str,
        action="append",
        default=[],
    )
    parser.add_argument(
        '-gr', '--guest_role',
        type=str.lower,
        required=True
    )
    parser.add_argument(
        '-subr', '--subscriber_role',
        type=str.lower,
        required=True
    )
    parser.add_argument(
        '-pr', '--premium_role',
        type=str.lower,
        required=True
    )
    parser.add_argument(
        '-stdr', '--standard_role',
        type=str.lower,
        required=True
    )
    parser.add_argument(
        '-pp', '--premium_price',
        type=int,
        required=True
    )
    parser.add_argument(
        '-sp', '--standard_price',
        type=int,
        required=True
    )
    parser.add_argument(
        '-stripe', '--stripe_channels',
        type=str,
        action='append',
        default=[]
    )
    parser.add_argument(
        '-sd', '--statement_descriptor',
        type=str,
        required=True
    )
    parser.add_argument(
        '-tt', '--trial_time',
        type=int,
        required=True
    )
    parser.add_argument(
        '-aid', '--admin_ids',
        type=str,
        action='append',
        default=[]
    )
    parser.add_argument('--bind', type=str)
    parser.add_argument('-m', type=str)
    parser.add_argument('wsgi:app', type=str)

    args = parser.parse_args()

    return args


class Dicts(object):
    user_info = {}
    queues = {}
    try:
        with open(get_path('dicts/expired.json')) as expired_file:
            expired = json.load(expired_file)
    except:
        expired = []
    try:
        with open(get_path('dicts/guest_expired_msg.txt')) as msg_file:
            guest_expired_msg = msg_file.read()
    except:
        guest_expired_msg = "Guest Trial has expired."
    try:
        with open(get_path('dicts/guest_used_msg.txt')) as msg_file:
            guest_used_msg = msg_file.read()
    except:
        guest_used_msg = (
            "Our records indicate that you have alerady used your free trial."
        )
