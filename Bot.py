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
        self.__stripe_channels = stripe_channels
        self.__user_info_channels = user_info_channels
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
            stripe_channel = None
            for channel_id in self.__stripe_channels:
                if self.get_channel(channel_id) is not None:
                    stripe_channel = self.get_channel(channel_id)
                    await stripe_channel.send(embed=em)
            if member is not None and stripe_channel is not None:
                log.info('Sent {} messgage for {} to stripe channel.'.format(
                    em.title, member))
            elif stripe_channel is not None:
                log.info('Sent {} message to stripe channel.'.format(em.title))
            else:
                log.error('Could not find stripe channel')
        if 'user_info_channel' in destinations:
            user_info_channel = None
            for channel_id in self.__user_info_channels:
                if self.get_channel(channel_id) is not None:
                    user_info_channel = self.get_channel(channel_id)
                    await user_info_channel.send(embed=em)
            if member is not None and user_info_channel is not None:
                log.info((
                    'Sent {} messgage for {} to user info channel.'
                ).format(em.title, member))
            elif user_info_channel is not None:
                log.info('Sent {} message to user info channel.'.format(
                    em.title))
            else:
                log.error('Could not find user info channel')
        if 'member' in destinations:
            try:
                await member.send(embed=em)
                log.info('Sent {} messgage to {}'.format(
                    em.title, member))
            except (AttributeError, discord.Forbidden):
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
                em = discord.Embed(
                    title=(
                        u"\U0001F6A9" + ' User logged in with flagged device!'
                    ),
                    description=payload['name'],
                    color=int('0xee281f', 16)
                )
                em.add_field(
                    name='Id',
                    value=payload['discord_id']
                )
                devices = '```\n'
                for name in payload['shared_with']:
                    devices += '{}\n'.format(name)
                devices += '```'
                em.add_field(
                    name='Shared devices with',
                    value=devices,
                    inline=False
                )
                em.set_footer(
                    text=str(datetime.now().strftime("%m/%d/%Y at %I:%M %p"))
                )
                await self.send_msg(em, member, ['user_info_channel'])
            elif payload['event'] == 'shared_device':
                em = discord.Embed(
                    title=(
                        u"\U0001F5A5" + ' User logged in with shared device!'
                    ),
                    description=payload['name'],
                    color=int('0x71cd40', 16)
                )
                em.add_field(
                    name='Id',
                    value=payload['discord_id']
                )
                devices = '```\n'
                for name in payload['shared_with']:
                    devices += '{}\n'.format(name)
                devices += '```'
                em.add_field(
                    name='Shared devices with',
                    value=devices,
                    inline=False
                )
                em.set_footer(
                    text=str(datetime.now().strftime("%m/%d/%Y at %I:%M %p"))
                )
                await self.send_msg(em, member, ['user_info_channel'])
            elif payload['event'] == 'new_user':
                em = discord.Embed(
                    title=u"\U0001F195" + ' New user logged in!',
                    description=payload['name'],
                    color=int('0x71cd40', 16)
                )
                em.add_field(
                    name='Id',
                    value=payload['discord_id']
                )
                servers = '```\n'
                for guild in payload['guilds']:
                    if len(servers) + len(guild) > 1016:
                        servers += '...\n'
                        break
                    servers += '{}\n'.format(guild)
                servers += '```'
                em.add_field(
                    name='Servers',
                    value=servers,
                    inline=False
                )
                em.set_footer(
                    text=str(datetime.now().strftime("%m/%d/%Y at %I:%M %p"))
                )
                await self.send_msg(em, member, ['user_info_channel'])
            elif payload['event'] == 'new_guilds':
                em = discord.Embed(
                    title=u"\U0001F195" + ' User joined new guild(s)!',
                    description=payload['name'],
                    color=int('0x71cd40', 16)
                )
                em.add_field(
                    name='Id',
                    value=payload['discord_id']
                )
                servers = '```\n'
                for guild in payload['new_guilds']:
                    if len(servers) + len(guild) > 1016:
                        servers += '...\n'
                        break
                    servers += '{}\n'.format(guild)
                servers += '```'
                em.add_field(
                    name='New Servers',
                    value=servers,
                    inline=False
                )
                em.set_footer(
                    text=str(datetime.now().strftime("%m/%d/%Y at %I:%M %p"))
                )
                await self.send_msg(em, member, ['user_info_channel'])
            elif payload['event'] == 'banned':
                em = discord.Embed(
                    title=u"\u274C" + ' Unauthorized login attempt!',
                    description=payload['name'],
                    color=int('0xee281f', 16)
                )
                em.add_field(
                    name='Id',
                    value=payload['discord_id']
                )
                em.set_footer(
                    text=str(datetime.now().strftime("%m/%d/%Y at %I:%M %p"))
                )
                await self.send_msg(em, member, ['user_info_channel'])
            elif payload['event'] == 'charge.succeeded':
                if 'message' not in payload:
                    em = discord.Embed(
                        title='\U0001f4b5 Payment Successful!',
                        description=str(member),
                        color=int('0x71cd40', 16)
                    )
                    em.add_field(
                        name='Id',
                        value=payload['discord_id']
                    )
                    em.add_field(
                        name='Amount',
                        value='${:,.2f}'.format(payload['amount'] / 100)
                    )
                    em.set_footer(
                        text=str(datetime.now().strftime(
                            "%m/%d/%Y at %I:%M %p"))
                    )
                    await self.send_msg(
                        em, member, ['stripe_channel', 'member'])
                else:
                    em = discord.Embed(
                        title=u"\U0001F4B0" + ' One-Time Charge Successful!',
                        description=str(member),
                        color=int('0x71cd40', 16)
                    )
                    em.add_field(
                        name='Id',
                        value=payload['discord_id']
                    )
                    em.add_field(
                        name='Amount',
                        value='${:,.2f}'.format(payload['amount']/100)
                    )
                    em.add_field(
                        name='Message',
                        value=payload['message']
                    )
                    em.set_footer(
                        text=str(datetime.now().strftime(
                            "%m/%d/%Y at %I:%M %p"))
                    )
                    await self.send_msg(
                        em, member, ['stripe_channel', 'member'])
            elif payload['event'] == 'customer.subscription.created':
                if member is not None:
                    await self.role_check(member)
                em = discord.Embed(
                    title=u"\u2705" + ' Subscription Created!',
                    description=str(member),
                    color=int('0x71cd40', 16)
                )
                em.add_field(
                    name='Id',
                    value=payload['discord_id']
                )
                em.add_field(
                    name='Plan',
                    value=payload['plan']
                )
                em.set_footer(
                    text=str(datetime.now().strftime("%m/%d/%Y at %I:%M %p"))
                )
                await self.send_msg(em, member, ['stripe_channel', 'member'])
            elif payload['event'] == 'customer.subscription.deleted':
                if member is not None:
                    premium_role = discord.utils.get(
                        member.guild.roles,
                        name=self.__premium_role
                    )
                    await member.remove_roles(premium_role)
                    log.info('Removed {} role from {}.'.format(
                        premium_role, member))
                    await self.role_check(member)
                em = discord.Embed(
                    title=u"\u274C" + ' Subscription Deleted!',
                    description=str(member),
                    color=int('0x71cd40', 16)
                )
                em.add_field(
                    name='Id',
                    value=payload['discord_id']
                )
                em.add_field(
                    name='Plan',
                    value=payload['plan']
                )
                em.set_footer(
                    text=str(datetime.now().strftime("%m/%d/%Y at %I:%M %p"))
                )
                await self.send_msg(em, member, ['stripe_channel', 'member'])
            elif payload['event'] == 'customer.subscription.updated':
                if payload['type'] == 'canceled':
                    em = discord.Embed(
                        title='\U0001f494 Subscription Canceled!',
                        description=str(member),
                        color=int('0x71cd40', 16)
                    )
                    em.add_field(
                        name='Id',
                        value=payload['discord_id']
                    )
                    em.add_field(
                        name='Plan',
                        value=payload['plan']
                    )
                    em.set_footer(
                        text=str(datetime.now().strftime(
                            "%m/%d/%Y at %I:%M %p"))
                    )
                else:
                    em = discord.Embed(
                        title=u"\U0001F389" + ' Subscription Reactivated!',
                        description=str(member),
                        color=int('0x71cd40', 16)
                    )
                    em.add_field(
                        name='Id',
                        value=payload['discord_id']
                    )
                    em.add_field(
                        name='Plan',
                        value=payload['plan']
                    )
                    em.set_footer(
                        text=str(datetime.now().strftime(
                            "%m/%d/%Y at %I:%M %p"))
                    )
                await self.send_msg(em, member, ['stripe_channel', 'member'])
            elif payload['event'] == 'customer.updated':
                em = discord.Embed(
                    title='\U0001F4B3 Customer Information Updated!',
                    description=str(member),
                    color=int('0x71cd40', 16)
                )
                em.add_field(
                    name='Id',
                    value=payload['discord_id']
                )
                if 'email' in payload:
                    em.add_field(
                        name='New Email',
                        value=payload['email']
                    )
                    em.add_field(
                        name='Old Email',
                        value=payload['old_email']
                    )
                if 'last4' in payload:
                    em.add_field(
                        name='New Card',
                        value='{} ...{}'.format(
                            payload['brand'], payload['last4'])
                    )
                    em.add_field(
                        name='Exp',
                        value='{}/{}'.format(
                            payload['exp_month'], payload['exp_year'])
                    )
                if payload.get('zip') is not None:
                    em.add_field(
                        name='ZIP Code',
                        value=payload['zip']
                    )
                em.set_footer(
                    text=str(datetime.now().strftime("%m/%d/%Y at %I:%M %p"))
                )
                await self.send_msg(em, member, ['member'])
            elif payload['event'] == 'invoice.payment_failed':
                em = discord.Embed(
                    title=u"\u274C" + ' Payment Failed!',
                    description=str(member),
                    color=int('0xee281f', 16)
                )
                em.add_field(
                    name='Id',
                    value=payload['discord_id']
                )
                em.add_field(
                    name='Amount',
                    value='${:,.2f}'.format(payload['amount']/100)
                )
                em.add_field(
                    name='Attempt',
                    value='{} of 2'.format(payload['attempt'])
                )
                if payload['next_attempt'] is not None:
                    em.add_field(
                        name='Next Attempt',
                        value=str(datetime.fromtimestamp(
                            payload['next_attempt']))
                    )
                em.set_footer(
                    text=str(datetime.now().strftime("%m/%d/%Y at %I:%M %p"))
                )
                await self.send_msg(em, member, ['stripe_channel', 'member'])
            elif payload['event'] == 'invoice.upcoming':
                em = discord.Embed(
                    title='\U0001f4e8 Payment Upcoming!',
                    description=str(member),
                    color=int('0x71cd40', 16)
                )
                em.add_field(
                    name='Id',
                    value=payload['discord_id']
                )
                em.add_field(
                    name='Amount',
                    value='${:,.2f}'.format(payload['amount']/100)
                )
                em.add_field(
                    name='Automatic Renewal Date',
                    value=str((datetime.now() + timedelta(days=3)).strftime(
                        "%m/%d/%Y"))
                )
                em.set_footer(
                    text=str(datetime.now().strftime("%m/%d/%Y at %I:%M %p"))
                )
                await self.send_msg(em, member, ['member'])
            self.__queue.task_done()

    async def role_check(self, member):
        premium_role = discord.utils.get(
            member.guild.roles,
            name=self.__premium_role
        )
        standard_role = discord.utils.get(
            member.guild.roles,
            name=self.__standard_role
        )
        con = sqlite3.connect('oauth2.db')
        cur = con.cursor()
        cur.execute(
            'SELECT stripe_id, plan, user, json_extract(guilds, ?)'
            'FROM userInfo '
            'WHERE discord_id = ?',
            ('$.{}'.format(member.guild.id), str(member.id))
        )
        user_dict = cur.fetchone()
        if ((user_dict is not None and user_dict[0] is not None) or
                member.top_role >= premium_role):
            plan = str(premium_role)
        elif member.top_role >= standard_role:
            plan = str(standard_role)
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
        if plan == str(premium_role) and member.top_role < premium_role:
            await member.add_roles(premium_role)
            log.info('Added {} role to {}.'.format(premium_role, member))
        elif plan != str(premium_role) and premium_role in member.roles:
            await member.remove_roles(premium_role)
            log.info('Removed {} role from {}.'.format(premium_role, member))

    async def on_ready(self):
        log.info("----------- Bot '{}' is starting up.".format(self.__name))
        for guild in self.guilds:
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
        if before.top_role != after.top_role or str(before) != str(after):
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
        if (message.channel.id in self.__user_info_channels and
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
                    await message.channel.send(embed=em)
                    log.info('{} sent an invalid user id.'.format(
                        message.author))
                    return
                member = discord.utils.get(
                    self.get_all_members(),
                    id=member_id
                )
            con = sqlite3.connect(
                'oauth2.db',
                detect_types=sqlite3.PARSE_DECLTYPES
            )
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
                await message.channel.send(embed=em)
                await message.delete()
                log.info('Cannot find user id {}.'.format(member_id))
            else:
                em = discord.Embed(
                    title='User info!',
                    description=user_dict[0],
                    color=int('0x71cd40', 16)
                )
                em.add_field(
                    name='Id',
                    value=str(member_id)
                )
                em.add_field(
                    name='Plan',
                    value=str(user_dict[1])
                )
                guilds = json.loads(user_dict[2])
                servers = '```\n'
                for guild_id in guilds:
                    if len(servers) + len(guilds[guild_id]) > 1016:
                        servers += '...\n'
                        break
                    servers += '{}\n'.format(guilds[guild_id])
                servers += '```'
                em.add_field(
                    name='Servers',
                    value=servers,
                    inline=False
                )
                shared_devices = json.loads(user_dict[3])
                if len(shared_devices) > 0:
                    devices = '```\n'
                    for user_id in shared_devices:
                        devices += '{}\n'.format(shared_devices[user_id])
                    devices += '```'
                    em.add_field(
                        name='Shared devices with',
                        value=devices,
                        inline=False
                    )
                if user_dict[4] is not None:
                    em.set_footer(
                        text='Updated: {}'.format(
                            user_dict[4].strftime("%m/%d/%Y at %I:%M %p"))
                    )
                if member is not None:
                    em.set_thumbnail(url=member.avatar_url)
                await message.channel.send(embed=em)
                await message.delete()
                log.info('Sent user info for {}'.format(user_dict[0]))
