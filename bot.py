#!/usr/bin/python3
# -*- coding: utf-8 -*-

import logging
import threading
import discord
import asyncio
import json
from queue import Queue
from datetime import datetime, timedelta
from utils import get_path, get_args, Dicts

logging.basicConfig(
    format='[%(name)10.10s][%(levelname)8.8s] %(message)s',
    level=logging.INFO
)
log = logging.getLogger('Bot')
logging.getLogger("discord").setLevel(logging.ERROR)
logging.getLogger("websockets").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)

args = get_args()


class Bot(discord.Client):

    users = {}
    guilds = {}
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

    async def role_check(client, member):
        roles = Bot.guilds[member.guild.id]['roles']
        regions = Bot.guilds[member.guild.id]['regions']
        if str(member.id) not in Bot.users
           Bot.users[str(member.id)] = {
               'stripe_id': None,
               'guilds': []
            }
        if Bot.users[str(member.id)]['stripe_id'] is None:
            if roles[args.premium_role] >= member.top_role:
                user['plan'] = args.premium_role
            elif roles[args.standard_role] in member.roles:
                user['plan'] = args.standard_role
            else:
                user['plan'] = None
        if (Bot.users[str(member.id)]['plan'] == args.premium_role and
                roles[args.premium_role] > member.top_role):
            await member.add_roles(roles[args.premium_role])
            log.info('Added `{}` role to `{}`.'.format(
                args.premium_role.title(), member.display_name))
        elif (Bot.users[str(member.id)]['plan'] != args.premium_role and
              roles[args.premium_role] in member.roles):
            await member.remove_roles(roles[args.premium_role])
            log.info('Removed `{}` role from `{}`.'.format(
                args.premium_role.title(), member.display_name))
        elif (Bot.users[str(member.id)]['plan'] == args.standard_role and
              roles[args.standard_role] not in member.roles):
            await member.add_roles(roles[args.standard_role])
            log.info('Added `{}` role to `{}`.'.format(
                args.standard_role.title(), member.display_name))
        elif (Bot.users[str(member.id)]['plan'] != args.standard_role and
              roles[args.standard_role] in member.roles):
            await member.remove_roles(roles[args.standard_role])
            log.info('Removed `{}` role from `{}`.'.format(
                args.standard_role.title(), member.display_name))
        elif ((roles[args.premium_role] in member.roles or
               roles[args.standard_role] in member.roles) and
              roles[args.subscriber_role] not in member.roles):
            await member.add_roles(roles[args.subscriber_role])
            log.info('Added `{}` role to `{}`.'.format(
                args.subscriber_role.title(), member.display_name))
        elif (roles[args.premium_role] not in member.roles and
              roles[args.standard_role] not in member.roles and
              roles[args.subscriber_role] in member.roles):
            await member.remove_roles(roles[args.subscriber_role])
            log.info('Removed `{}` role from `{}`.'.format(
                args.subscriber_role.title(), member.display_name))
        elif (Bot.users[str(member.id)]['plan'] is not None and
              roles[args.guest_role] in member.roles):
            await member.remove_roles(roles[args.guest_role])
            log.info('Removed `{}` role from `{}`.'.format(
                args.guest_role.title(), member.display_name))
        else:
            for region in regions:
                region_subscriber_role = roles[
                    region + '-' + args.subscriber_role]
                if ((Bot.users[str(member.id)]['plan'] is not None or
                     roles[args.guest_role] in member.roles) and
                    roles[region] in member.roles and
                        region_subscriber_role not in member.roles):
                    await member.add_roles(region_subscriber_role)
                    log.info('Added `{}` role to `{}`.'.format(
                        region_subscriber_role.name.title(),
                        member.display_name
                    ))
                elif (((Bot.users[str(member.id)]['plan'] is None and
                        roles[args.guest_role] not in member.roles) or
                       roles[region] not in member.roles) and
                      region_subscriber_role in member.roles):
                    await member.remove_roles(region_subscriber_role)
                    log.info('Removed `{}` role from `{}`.'.format(
                        region_subscriber_role.name.title(),
                        member.display_name
                    ))

    async def guest_check(client, q, stripe_channel):
        guests = {}
        for member in client.get_all_members():
            if roles[args.guest_role] in member.roles:
                time_left = round(args.trial_time - (
                    datetime.utcnow() - member.joined_at).total_seconds())
                if time_left >= 0:
                    guests[time_left] = member
                else:
                    await member.remove_roles(roles[args.guest_role])
                    try:
                        await member.send(Bot.guest_expired_msg)
                        log.info((
                            'Removed `{}` role from `{}` and sent guest ' +
                            'expired message.'
                        ).format(args.guest_role.title(), member.display_name))
                    except:
                        log.info((
                            'Removed `{}` role from `{}` but unable to send ' +
                            'guest expired message.'
                        ).format(args.guest_role.title(), member.display_name))
        log.info('Waiting `{}` seconds for next guest check.'.format(
            min(min(guests) + 5, args.trial_time)))
        await Bot.webhook(
            client, q, stripe_channel, min(min(guests) + 5, args.trial_time)
        )

    async def webhook(client, q, stripe_channel, wait_time):
        end_time = datetime.utcnow() + timedelta(seconds=wait_time)
        while datetime.utcnow() <= end_time:
            while q.empty() and datetime.utcnow() <= end_time:
                await asyncio.sleep(1)
            if datetime.utcnow() > end_time:
                break
            payload = q.get()
            member = discord.utils.get(
                client.get_all_members(),
                id=payload['discord_id']
            )
            if payload['event'] == 'charge.succeeded':
                if 'area' not in payload:
                    em = discord.Embed(
                        title='\U0001f4b5 Payment Successful!',
                        description=(
                            str(member) +
                            '\n\n**Id**\n' + str(member.id) +
                            '\n\n**Amount**\n${:,.2f}'.format(
                                payload['amount']/100) +
                            '\n\n' + str(datetime.time(datetime.now().replace(
                                microsecond=0)))
                        ),
                        color=int('0x71cd40', 16)
                    )
                    em.set_thumbnail(url=member.avatar_url)
                    await stripe_channel.send(embed=em)
                    log.info((
                        'Sent `{}` messgage for `{}` to stripe channel.'
                    ).format(em.title, member.display_name))
                else:
                    em = discord.Embed(
                        title=u"\U0001F4B0" + ' One-Time Charge Successful!',
                        description=(
                            str(member) +
                            '\n\n**Id**\n' + str(member.id) +
                            '\n\n**Amount**\n${:,.2f}'.format(
                                payload['amount']/100) +
                            '\n\n**Area Requested**\n' + payload['area'] +
                            '\n\n' + str(datetime.time(datetime.now().replace(
                                microsecond=0)))
                        ),
                        color=int('0x71cd40', 16)
                    )
                    em.set_thumbnail(url=member.avatar_url)
                    await stripe_channel.send(embed=em)
                    if 'sent' not in payload:
                        for admin in args.admin_ids:
                            await discord.utils.get(
                                client.get_all_members(),
                                id=admin
                            ).send(embed=em)
                    log.info((
                        'Sent `{}` messgage for `{}` to stripe channel and ' +
                        'admins.'
                    ).format(em.title, member.display_name))
            elif (payload['event'] == 'customer.discount.created' or
                  payload['event'] == 'customer.discount.updated'):
                em = discord.Embed(
                    title=u"\U0001F39F" + ' Coupon Applied!',
                    description=(
                        str(member) +
                        '\n\n**Id**\n' + str(member.id) +
                        '\n\n**Coupon**\n' + payload['coupon'] +
                        '\n\n**Discount**\n' + payload['discount'] +
                        '\n\n**Duration**\n' + payload['duration'] +
                        '\n\n' + str(datetime.time(datetime.now().replace(
                             microsecond=0)))
                    ),
                    color=int('0x71cd40', 16)
                )
                em.set_thumbnail(url=member.avatar_url)
                await stripe_channel.send(embed=em)
                log.info((
                    'Sent `{}` messgage for `{}` to stripe channel.'
                ).format(em.title, member.display_name))
            elif payload['event'] == 'customer.subscription.created':
                await Bot.role_check(client, member)
                em = discord.Embed(
                    title=u"\u2705" + ' Subscription Created!',
                    description=(
                        str(member) +
                        '\n\n**Id**\n' + str(member.id) +
                        '\n\n**Plan**\n' + payload['plan'] +
                        '\n\n' + str(datetime.time(datetime.now().replace(
                                     microsecond=0)))
                    ),
                    color=int('0x71cd40', 16)
                )
                em.set_thumbnail(url=member.avatar_url)
                await stripe_channel.send(embed=em)
                log.info((
                    'Sent `{}` messgage for `{}` to stripe channel.'
                ).format(em.title, member.display_name))
            elif payload['event'] == 'customer.subscription.deleted':
                await Bot.role_check(client, member)
                em = discord.Embed(
                    title=u"\u274C" + ' Subscription Deleted!',
                    description=(
                        str(member) +
                        '\n\n**Id**\n' + str(member.id) +
                        '\n\n**Plan**\n' + payload['plan'] +
                        '\n\n' + str(datetime.time(datetime.now().replace(
                                     microsecond=0)))
                    ),
                    color=int('0xee281f', 16)
                )
                em.set_thumbnail(url=member.avatar_url)
                await stripe_channel.send(embed=em)
                log.info((
                    'Sent `{}` messgage for `{}` to stripe channel.'
                ).format(em.title, member.display_name))
            elif payload['event'] == 'customer.subscription.updated':
                if payload['type'] == 'canceled':
                    em = discord.Embed(
                        title='\U0001f494 Subscription Canceled!',
                        description=(
                            str(member) +
                            '\n\n**Id**\n' + str(member.id) +
                            '\n\n**Plan**\n' + payload['plan'] +
                            '\n\n' + str(datetime.time(
                                datetime.now().replace(microsecond=0)))
                        ),
                        color=int('0xee281f', 16)
                    )
                elif payload['type'] == 'upgraded':
                    await Bot.role_check(client, member)
                    em = discord.Embed(
                        title='\U0001f53c Subscription Upgraded!',
                        description=(
                            str(member) +
                            '\n\n**Id**\n' + str(member.id) +
                            '\n\n**New Plan\n**' + payload['plan'] +
                            '\n\n**Old Plan\n**' + payload['old_plan'] +
                            '\n\n' + str(datetime.time(
                                 datetime.now().replace(microsecond=0)))
                        ),
                        color=int('0x71cd40', 16)
                    )
                elif payload['type'] == 'downgraded':
                    await Bot.role_check(client, member)
                    em = discord.Embed(
                        title='\U0001f53d Subscription Downgraded!',
                        description=(
                            str(member) +
                            '\n\n**Id**\n' + str(member.id) +
                            '\n\n**New Plan**\n' + payload['plan'] +
                            '\n\n**Old Plan**\n' + payload['old_plan'] +
                            '\n\n' + str(datetime.time(
                                 datetime.now().replace(microsecond=0)))
                        ),
                        color=int('0xee281f', 16)
                    )
                em.set_thumbnail(url=member.avatar_url)
                await stripe_channel.send(embed=em)
                log.info((
                    'Sent `{}` messgage for `{}` to stripe channel.'
                ).format(em.title, member.display_name))
            elif payload['event'] == 'customer.updated':
                descript = (
                    str(member) +
                    '\n\n**Id**\n' + str(member.id)
                )
                if 'email' in payload:
                    descript += (
                        '\n\n**New Email**\n' + payload['email'] +
                        '\n\n**Old Email**\n' + payload['old_email']
                    )
                if 'last4' in payload:
                    descript += (
                        '\n\n**New Card**\n' + payload['brand'] + ' ...' +
                        payload['last4'] +
                        '\n\n**Exp**\n' + str(payload['exp_month']) + '/' +
                        str(payload['exp_year'])
                    )
                if payload.get('zip') is not None:
                    descript += '\n\n**ZIP Code**\n' + payload['zip']
                descript += (
                    '\n\n' + str(datetime.time(datetime.now().replace(
                        microsecond=0)))
                )
                em = discord.Embed(
                    title='\U0001F4B3 Customer Information Updated!',
                    description=descript,
                    color=int('0x71cd40', 16)
                )
                em.set_thumbnail(url=member.avatar_url)
            elif payload['event'] == 'invoice.payment_failed':
                descript = (
                    str(member) +
                    '\n\n**Id**\n' + str(member.id) +
                    '\n\n**Amount**\n${:,.2f}'.format(payload['amount']/100) +
                    '\n\n**Attempt**\n' + str(payload['attempt']) + ' of 3'
                )
                if payload['next_attempt'] is not None:
                    descript += (
                        '\n\n**Next Attempt**\n' +
                        str(datetime.fromtimestamp(payload['next_attempt']))
                    )
                descript += (
                    '\n\n' + str(datetime.time(datetime.now().replace(
                        microsecond=0)))
                )
                em = discord.Embed(
                    title=u"\u274C" + ' Payment Failed!',
                    description=descript,
                    color=int('0xee281f', 16)
                )
                em.set_thumbnail(url=member.avatar_url)
                await stripe_channel.send(embed=em)
                if 'sent' not in payload:
                    for admin in args.admin_ids:
                        await discord.utils.get(
                            client.get_all_members(),
                            id=admin
                        ).send(embed=em)
                log.info((
                    'Sent `{}` messgage for `{}` to stripe channel and admins.'
                ).format(em.title, member.display_name))
            elif payload['event'] == 'invoice.upcoming':
                em = discord.Embed(
                    title='\U0001f4e8 Payment Upcoming!',
                    description=(
                        str(member) +
                        '\n\n**Id**\n' + str(member.id) +
                        '\n\n**Amount**\n${:,.2f}'.format(
                            payload['amount']/100) +
                        '\n\n**Automatic Renewal Date**\n' + str(datetime.date(
                            datetime.now() + timedelta(days=3))) +
                        '\n\n' + str(datetime.time(datetime.now().replace(
                            microsecond=0)))
                    ),
                    color=int('0x71cd40', 16)
                )
                em.set_thumbnail(url=member.avatar_url)
            if 'sent' not in payload:
                try:
                    await member.send(embed=em)
                    log.info('Sent `{}` messgage to `{}`'.format(
                        em.title, member.display_name))
                except:
                    log.info('Unable to send `{}` message to `{}`'.format(
                        em.title, member.display_name))
            q.task_done()
        await Bot.guest_check(client)

    async def on_ready(self):
        for guild in self.guilds:
            Bot.guilds[guild.id] = {
                'q': Queue(),
                'roles': {},
                'regions': []
            }
            q = Bot.guilds[guild.id]['q']
            for channel in guild.channels:
                if channel.id in args.stripe_channels:
                    stripe_channel = channel
                    break
            for role in guild.roles:
                Bot.guilds[guild.id][roles][role.name.lower()] = role
                if role.name.lower().endswith('-' + args.subscriber_role):
                    Bot.guilds[guild.id][regions].append(
                        role.name.lower().replace(
                            '-' + args.subscriber_role, ''))
        changed = False
        for member in self.get_all_members():
            if str(member.id) not in Bot.expired:
                Bot.expired.append(str(member.id))
                changed = True
            await Bot.role_check(self, member)
        if changed is True:
            with open(get_path('dicts/expired.json'), 'w') as expired_file:
                json.dump(Bot.expired, expired_file, indent=4)
        await Bot.guest_check(self, q, stripe_channel)

    async def on_member_join(self, member):
        if (str(member.id) in Bot.users and
            Bot.users[str(member.id)]['plan'] == args.premium_role):
            await member.add_roles(roles[args.premium_role])
            log.info('Added `{}` role to `{}`.'.format(
                args.premium_role, member.display_name))
            if str(member.id) not in Bot.expired:
                Bot.expired.append(str(member.id))
                with open(get_path('dicts/expired.json'), 'w') as expired_file:
                    json.dump(Bot.expired, expired_file, indent=4)
        elif (str(member.id) in Bot.users and
              Bot.users[str(member.id)]['plan'] == args.standard_role):
            await member.add_roles(roles[args.standard_role])
            log.info('Added `{}` role to `{}`.'.format(
                args.standard_role, member.display_name))
            if str(member.id) not in Bot.expired:
                Bot.expired.append(str(member.id))
                with open(get_path('dicts/expired.json'), 'w') as expired_file:
                    json.dump(Bot.expired, expired_file, indent=4)
        elif (str(member.id) not in Bot.users and
              str(member.id) not in Bot.expired):
            await member.add_roles(roles[args.guest_role])
            log.info('Added `{}` role to `{}`.'.format(
                args.guest_role, member.display_name))
            if str(member.id) not in Bot.expired:
                Bot.expired.append(str(member.id))
                with open(get_path('dicts/expired.json'), 'w') as expired_file:
                    json.dump(Bot.expired, expired_file, indent=4)
        else:
            Bot.users[str(member.id)] = {
               'stripe_id': None,
               'guilds': [member.guild.id],
               'plan': None
            }
            try:
                await member.send(Bot.guest_used_msg)
                log.info('Sent `{}` guest used message.'.format(
                    member.display_name))
            except:
                log.info('Unable to send `{}` guest used message.'.format(
                    member.display_name))
            for admin in args.admin_ids:
                await discord.utils.get(
                    self.get_all_members(),
                    id=admin
                ).send(
                    '`{}` joined the server but was not assigned the guest ' +
                    'role since they have been here before.'
                ).format(member.display_name)
            log.info('Messaged admins on `{}` join.'.format(
                member.display_name))
            await Bot.role_check(self, member)

    async def on_member_update(self, before, after):
        if before.roles != after.roles:
            await Bot.role_check(self, after)

    async def on_member_remove(self, member):
        if Bot.users[str(member.id)]['stripe_id'] is not None:
            Bot.users[str(member.id)]['guilds'].remove(member.guild.id)
            log.info('Removed `{}` from the server dict.'.format(
                member.display_name))
        else:
            Bot.users.pop(str(member.id))
            log.info('Removed `{}` from  dict.'.format(
                member.display_name))

    async def on_message(self, message):
        if message.content.lower() == 'ping':
            await message.channel.send('pong')
            log.info('Sent ping message to `{}`.'.format(
                message.author.display_name))
