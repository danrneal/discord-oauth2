import asyncio
import discord
import json
import logging
import sqlite3
from datetime import datetime, timedelta
from queue import Queue

log = logging.getLogger('Bot')


class Bot(discord.Client):

    def __init__(self, name, premium_role, standard_role, stripe_channels,
                 user_info_channels, token, loop):
        super(Bot, self).__init__()
        self.__token = token
        self.__name = name
        self.__premium_role = premium_role
        self.__standard_role = standard_role
        self.__stripe_channel = stripe_channels
        self.__user_info_channel = user_info_channels
        self.__queue = Queue()

    def get_name(self):
        return self.__name

    def get_token(self):
        return self.__token

    def get_queue(self):
        return self.__queue

    async def send_msg(self, em, member, destinations):
        if member is not None:
            em.set_thumbnail(url=member.avatar_url)
        if 'stripe_channel' in destinations:
            await self.__stripe_channel.send(embed=em)
            if member is not None:
                log.info('Sent {} messgage for {} to stripe channel.'.format(
                    em.title, member))
            else:
                log.info('Sent {} message to stripe channel.'.format(em.title))
        if 'user_info_channel' in destinations:
            await self.__user_info_channel.send(embed=em)
            if member is not None:
                log.info((
                    'Sent {} messgage for {} to user info channel.'
                ).format(em.title, member))
            else:
                log.info('Sent {} message to user info channel.'.format(
                    em.title))
        if 'member' in destinations:
            try:
                await member.send(embed=em)
                log.info('Sent {} messgage to {}'.format(
                    em.title, member))
            except discord.Forbidden:
                log.info('Unable to send {} message to {}'.format(
                    em.title, member))

    async def webhook(self):
        while True:
            if self.__queue.empty():
                await asyncio.sleep(1)
                continue
            payload = self.__queue.get()
            member = discord.utils.get(
                self.get_all_members(),
                id=int(payload['discord_id'])
            )
            if payload['event'] == 'flagged_device':
                descript = (
                    payload['name'] +
                    '\n\n**Id**\n' + payload['discord_id'] +
                    '\n\n**Shared With**\n```\n'
                )
                for name in payload['shared_with']:
                    descript += name + '\n'
                descript += '```\n' + str(datetime.time(datetime.now().replace(
                    microsecond=0)))
                em = discord.Embed(
                    title=(
                        u"\U0001F6A9" + ' User logged in with flagged device!'
                    ),
                    description=descript,
                    color=int('0xee281f', 16)
                )
                await self.send_msg(em, member, ['user_info_channel'])
            elif payload['event'] == 'shared_device':
                descript = (
                    payload['name'] +
                    '\n\n**Id**\n' + payload['discord_id'] +
                    '\n\n**Shared With**\n```\n'
                )
                for name in payload['shared_with']:
                    descript += name + '\n'
                descript += '```\n' + str(datetime.time(datetime.now().replace(
                    microsecond=0)))
                em = discord.Embed(
                    title=(
                        u"\U0001F5A5" + ' User logged in with shared device!'
                    ),
                    description=descript,
                    color=int('0x71cd40', 16)
                )
                await self.send_msg(em, member, ['user_info_channel'])
            elif payload['event'] == 'new_user':
                descript = (
                    payload['name'] +
                    '\n\n**Id**\n' + payload['discord_id'] +
                    '\n\n**Servers**\n```\n'
                )
                for guild in payload['guilds']:
                    descript += guild + '\n'
                descript += '```\n' + str(datetime.time(datetime.now().replace(
                    microsecond=0)))
                em = discord.Embed(
                    title=u"\U0001F195" + ' New user logged in!',
                    description=descript,
                    color=int('0x71cd40', 16)
                )
                await self.send_msg(em, member, ['user_info_channel'])
            elif payload['event'] == 'new_guilds':
                descript = (
                    payload['name'] +
                    '\n\n**Id**\n' + payload['discord_id'] +
                    '\n\n**New Servers**\n```\n'
                )
                for guild in payload['new_guilds']:
                    descript += guild + '\n'
                descript += '```\n' + str(datetime.time(datetime.now().replace(
                    microsecond=0)))
                em = discord.Embed(
                    title=u"\U0001F195" + ' User joined new guild(s)!',
                    description=descript,
                    color=int('0x71cd40', 16)
                )
                await self.send_msg(em, member, ['user_info_channel'])
            elif payload['event'] == 'banned':
                em = discord.Embed(
                    title=u"\u274C" + ' Unauthorized login attempt!',
                    description=(
                        payload['name'] +
                        '\n\n**Id**\n' + payload['discord_id'] +
                        '\n\n' + str(datetime.time(datetime.now().replace(
                            microsecond=0)))
                    ),
                    color=int('0xee281f', 16)
                )
                await self.send_msg(em, member, ['user_info_channel'])
            elif payload['event'] == 'charge.succeeded':
                if 'message' not in payload:
                    em = discord.Embed(
                        title='\U0001f4b5 Payment Successful!',
                        description=(
                            str(member) +
                            '\n\n**Id**\n' + payload['discord_id'] +
                            '\n\n**Amount**\n${:,.2f}'.format(
                                payload['amount']/100) +
                            '\n\n' + str(datetime.time(datetime.now().replace(
                                microsecond=0)))
                        ),
                        color=int('0x71cd40', 16)
                    )
                    await self.send_msg(
                        em, member, ['stripe_channel', 'member'])
                else:
                    em = discord.Embed(
                        title=u"\U0001F4B0" + ' One-Time Charge Successful!',
                        description=(
                            str(member) +
                            '\n\n**Id**\n' + payload['discord_id'] +
                            '\n\n**Amount**\n${:,.2f}'.format(
                                payload['amount']/100) +
                            '\n\n**Message**\n' + payload['message'] +
                            '\n\n' + str(datetime.time(datetime.now().replace(
                                microsecond=0)))
                        ),
                        color=int('0x71cd40', 16)
                    )
                    await self.send_msg(
                        em, member, ['stripe_channel', 'member'])
            elif payload['event'] == 'customer.subscription.created':
                if member is not None:
                    await self.role_check(member)
                em = discord.Embed(
                    title=u"\u2705" + ' Subscription Created!',
                    description=(
                        str(member) +
                        '\n\n**Id**\n' + payload['discord_id'] +
                        '\n\n**Plan**\n' + payload['plan'] +
                        '\n\n' + str(datetime.time(datetime.now().replace(
                                     microsecond=0)))
                    ),
                    color=int('0x71cd40', 16)
                )
                await self.send_msg(em, member, ['stripe_channel', 'member'])
            elif payload['event'] == 'customer.subscription.deleted':
                if member is not None:
                    await self.role_check(member)
                em = discord.Embed(
                    title=u"\u274C" + ' Subscription Deleted!',
                    description=(
                        str(member) +
                        '\n\n**Id**\n' + payload['discord_id'] +
                        '\n\n**Plan**\n' + payload['plan'] +
                        '\n\n' + str(datetime.time(datetime.now().replace(
                                     microsecond=0)))
                    ),
                    color=int('0xee281f', 16)
                )
                await self.send_msg(em, member, ['stripe_channel', 'member'])
            elif payload['event'] == 'customer.subscription.updated':
                if payload['type'] == 'canceled':
                    em = discord.Embed(
                        title='\U0001f494 Subscription Canceled!',
                        description=(
                            str(member) +
                            '\n\n**Id**\n' + payload['discord_id'] +
                            '\n\n**Plan**\n' + payload['plan'] +
                            '\n\n' + str(datetime.time(
                                datetime.now().replace(microsecond=0)))
                        ),
                        color=int('0xee281f', 16)
                    )
                else:
                    em = discord.Embed(
                        title=u"\U0001F389" + ' Subscription Reactivated!',
                        description=(
                            str(member) +
                            '\n\n**Id**\n' + payload['discord_id'] +
                            '\n\n**Plan**\n' + payload['plan'] +
                            '\n\n' + str(datetime.time(
                                datetime.now().replace(microsecond=0)))
                        ),
                        color=int('0x71cd40', 16)
                    )
                await self.send_msg(em, member, ['stripe_channel', 'member'])
            elif payload['event'] == 'customer.updated':
                descript = (
                    str(member) +
                    '\n\n**Id**\n' + payload['discord_id']
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
                await self.send_msg(em, member, ['member'])
            elif payload['event'] == 'invoice.payment_failed':
                descript = (
                    str(member) +
                    '\n\n**Id**\n' + payload['discord_id'] +
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
                await self.send_msg(em, member, ['stripe_channel', 'member'])
            elif payload['event'] == 'invoice.upcoming':
                em = discord.Embed(
                    title='\U0001f4e8 Payment Upcoming!',
                    description=(
                        str(member) +
                        '\n\n**Id**\n' + payload['discord_id'] +
                        '\n\n**Amount**\n${:,.2f}'.format(
                            payload['amount']/100) +
                        '\n\n**Automatic Renewal Date**\n' + str(datetime.date(
                            datetime.now() + timedelta(days=3))) +
                        '\n\n' + str(datetime.time(datetime.now().replace(
                            microsecond=0)))
                    ),
                    color=int('0x71cd40', 16)
                )
                await self.send_msg(em, member, ['member'])
            self.__queue.task_done()

    async def role_check(self, member):
        if (member.top_role >= self.__standard_role and
                member.nick is None and
                self.user.id != member.id):
            try:
                await member.edit(nick=member.display_name + '.')
                log.info("Locked {}'s nickname".format(member))
            except discord.Forbidden:
                pass
        con = sqlite3.connect('oauth2.db')
        cur = con.cursor()
        cur.execute(
            'SELECT stripe_id, plan, user, json_extract(guilds, ?)'
            'FROM userInfo '
            'WHERE discord_id = ?',
            ('$.{}'.format(member.guild.id), str(member.id))
        )
        user_dict = cur.fetchone()
        if ((user_dict is not None and
             user_dict[0] is not None) or
                member.top_role >= self.__premium_role):
            plan = str(self.__premium_role)
        elif member.top_role >= self.__standard_role:
            plan = str(self.__standard_role)
        elif user_dict is None:
            plan = None
        else:
            plan = user_dict[1]
        if user_dict is None:
            cur.execute(
                'INSERT INTO userInfo '
                '(discord_id, user, plan, shared_devices, guilds) '
                'VALUES (?, ?, ?, ?, ?)',
                (
                    str(member.id), str(member), plan, json.dumps({}),
                    json.dumps({str(member.guild.id): str(member.guild)})
                )
            )
            log.info("Added user info for {}".format(member))
        elif (user_dict[1] != plan or
              user_dict[2] != str(member) or
              user_dict[3] != str(member.guild)):
            cur.execute(
                'UPDATE userInfo '
                'SET user = ?, plan = ?, guilds = json_set(guilds, ?, ?) '
                'WHERE discord_id = ?',
                (
                    str(member), plan, '$.{}'.format(member.guild.id),
                    str(member.guild), str(member.id)
                )
            )
            if user_dict[2] != str(member):
                cur.execute(
                    'UPDATE userInfo '
                    'SET shared_devices = json_replace(shared_devices, ?, ?) '
                    'WHERE json_extract(shared_devices, ?) IS NOT NULL',
                    (
                        '$.{}'.format(member.id), str(member),
                        '$.{}'.format(member.id)
                    )
                )
            log.info('Updated user info for {}'.format(member))
        con.commit()
        con.close()
        if (plan == str(self.__premium_role) and
                member.top_role < self.__premium_role):
            await member.add_roles(self.__premium_role)
            log.info('Added {} role to {}.'.format(
                self.__premium_role, member))
        elif (plan != str(self.__premium_role) and
              self.__premium_role in member.roles):
            await member.remove_roles(self.__premium_role)
            log.info('Removed {} role from {}.'.format(
                self.__premium_role, member))

    async def on_ready(self):
        log.info("----------- Bot '{}' is starting up.".format(self.__name))
        for channel_id in self.__stripe_channel:
            if self.get_channel(channel_id) is not None:
                self.__stripe_channel = self.get_channel(channel_id)
        for channel_id in self.__user_info_channel:
            if self.get_channel(channel_id) is not None:
                self.__user_info_channel = self.get_channel(channel_id)
        for guild in self.guilds:
            self.__premium_role = discord.utils.get(
                guild.roles,
                name=self.__premium_role
            )
            self.__standard_role = discord.utils.get(
                guild.roles,
                name=self.__standard_role
            )
            for ban in await guild.bans():
                con = sqlite3.connect('oauth2.db')
                cur = con.cursor()
                cur.execute(
                    'SELECT user, plan '
                    'FROM userInfo '
                    'WHERE discord_id = ?',
                    (str(ban.user.id),)
                )
                user_dict = cur.fetchone()
                if user_dict is None:
                    cur.execute(
                        'INSERT INTO userInfo '
                        '(discord_id, user, plan, shared_devices, guilds) '
                        'VALUES (?, ?, ?, ?, ?)',
                        (
                            str(ban.user.id), str(ban.user), 'Banned',
                            json.dumps({}), json.dumps({})
                        )
                    )
                    log.info("Added {}'s user info".format(ban.user))
                elif user_dict[0] != str(ban.user) or user_dict[1] != 'Banned':
                    cur.execute(
                        'UPDATE userInfo '
                        'SET user = ?, plan = ? '
                        'WHERE discord_id = ?',
                        (str(ban.user), 'Banned', str(ban.user.id))
                    )
                    log.info("Updated {}'s user info".format(ban.user))
                con.commit()
                con.close()
        for member in self.get_all_members():
            await self.role_check(member)
        log.info("----------- Bot '{}' is connected.".format(self.__name))

    async def on_member_join(self, member):
        await self.role_check(member)

    async def on_member_update(self, before, after):
        if before.roles != after.roles or str(before) != str(after):
            await self.role_check(after)

    async def on_member_remove(self, member):
        con = sqlite3.connect('oauth2.db')
        cur = con.cursor()
        cur.execute(
            'SELECT stripe_id, plan '
            'FROM userInfo '
            'WHERE discord_id = ?',
            (str(member.id),)
        )
        user_dict = cur.fetchone()
        cur.execute(
            'UPDATE userInfo '
            'SET guilds = json_remove(guilds, ?) '
            'WHERE discord_id = ?',
            ('$.{}'.format(member.guild.id), str(member.id))
        )
        if user_dict[0] is None and user_dict[1] != 'Banned':
            cur.execute(
                'UPDATE userInfo '
                'SET plan = ? '
                'WHERE discord_id = ?',
                (None, str(member.id))
            )
        con.commit()
        con.close()
        log.info("{} left the server".format(member))

    async def on_member_ban(self, guild, member):
        con = sqlite3.connect('oauth2.db')
        cur = con.cursor()
        cur.execute(
            'UPDATE userInfo '
            'SET plan = ? '
            'WHERE discord_id = ?',
            ('Banned', str(member.id))
        )
        con.commit()
        con.close()
        log.info("Updated {}'s ban status".format(member))

    async def on_member_unban(self, guild, member):
        con = sqlite3.connect('oauth2.db')
        cur = con.cursor()
        cur.execute(
            'UPDATE userInfo '
            'SET plan = ? '
            'WHERE discord_id = ?',
            (None, str(member.id))
        )
        con.commit()
        con.close()
        log.info("Updated {}'s ban status".format(member))

    async def on_message(self, message):
        if message.content.lower() == 'ping':
            await message.channel.send('pong')
            await message.delete()
            log.info('Sent ping message to {}.'.format(message.author))
        if (message.channel == self.__user_info_channel and
                message.content.lower().startswith('!info ')):
            if len(message.mentions) == 1:
                member = message.mentions[0]
                member_id = member.id
            else:
                try:
                    member_id = int(message.content.lower().split()[1])
                except (ValueError, IndexError):
                    em = discord.Embed(
                        description='{} Not a valid user id.'.format(
                            message.author.mention),
                        color=int('0xee281f', 16)
                    )
                    await self.__user_info_channel.send(embed=em)
                    log.info('{} sent an invalid user id.'.format(
                        message.author))
                    return
                member = discord.utils.get(
                    self.get_all_members(),
                    id=member_id
                )
            con = sqlite3.connect('oauth2.db')
            cur = con.cursor()
            cur.execute(
                'SELECT user, plan, guilds, shared_devices, last_login '
                'FROM userInfo '
                'WHERE discord_id = ?',
                (str(member_id),)
            )
            user_dict = cur.fetchone()
            con.close()
            if user_dict is None:
                em = discord.Embed(
                    description='{} Cannot find user with id {}.'.format(
                        message.author.mention, member_id),
                    color=int('0xee281f', 16)
                )
                await self.__user_info_channel.send(embed=em)
                await message.delete()
                log.info('Cannot find user id {}.'.format(member_id))
            else:
                descript = (
                    user_dict[0] +
                    '\n\n**Id**\n' + str(member_id) +
                    '\n\n**Plan**\n' + str(user_dict[1]) +
                    '\n\n**Servers**\n```\n'
                )
                guilds = json.loads(user_dict[2])
                for guild_id in guilds:
                    descript += guilds[guild_id] + '\n'
                shared_devices = json.loads(user_dict[3])
                if len(shared_devices) > 0:
                    descript += '```\n\n**Shared devices with**\n```\n'
                    for user_id in shared_devices:
                        descript += shared_devices[user_id] + '\n'
                descript += '```\n\n**Updated**\n' + user_dict[4]
                em = discord.Embed(
                    title='User info!',
                    description=descript,
                    color=int('0x71cd40', 16)
                )
                if member is not None:
                    em.set_thumbnail(url=member.avatar_url)
                await self.__user_info_channel.send(embed=em)
                await message.delete()
                log.info('Sent user info for {}'.format(user_dict[0]))
