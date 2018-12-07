import asyncio
import configargparse
import json
import logging.handlers
import os
import sqlite3
import stripe
import sys
from collections import namedtuple
from datetime import datetime
from flask import Flask, session, redirect, request, render_template
from requests_oauthlib import OAuth2Session
from threading import Thread
from Bot import Bot
from utils import LoggerWriter

filehandler = logging.handlers.TimedRotatingFileHandler(
    'pokepaywall.log',
    when='midnight',
    backupCount=2,
    encoding='utf-8'
)
consolehandler = logging.StreamHandler()
logging.basicConfig(
    format=(
        '%(asctime)s [%(processName)15.15s][%(name)10.10s]' +
        '[%(levelname)8.8s] %(message)s'
    ),
    level=logging.INFO,
    handlers=[filehandler, consolehandler]
)

log = logging.getLogger('Server')
sys.stdout = LoggerWriter(log.info)
sys.stderr = LoggerWriter(log.warning)

app = Flask(__name__)
bots = {}
entries = []
queues = []


def token_updater(token):
    session['oauth2_token'] = token


def make_session(token=None, state=None, scope=None):
    return OAuth2Session(
        client_id=app.config['OAUTH2_CLIENT_ID'],
        token=token,
        state=state,
        scope=scope,
        redirect_uri=app.config['OAUTH2_REDIRECT_URI'],
        auto_refresh_kwargs={
            'client_id': app.config['OAUTH2_CLIENT_ID'],
            'client_secret': app.config['SECRET_KEY']
        },
        auto_refresh_url=app.config['TOKEN_URL'],
        token_updater=token_updater
    )


@app.route('/login')
def login():
    scope = request.args.get(
        'scope',
        'identify email guilds guilds.join'
    )
    discord = make_session(scope=scope.split(' '))
    authorization_url, state = discord.authorization_url(
        app.config['AUTHORIZATION_BASE_URL'])
    session['oauth2_state'] = state
    return redirect(authorization_url)


@app.route('/login/callback')
def callback():
    if request.values.get('error'):
        return request.values['error']
    discord = make_session(state=session.get('oauth2_state'))
    try:
        token = discord.fetch_token(
            app.config['TOKEN_URL'],
            client_secret=app.config['SECRET_KEY'],
            authorization_response=request.url.strip()
        )
        session['oauth2_token'] = token
        return redirect('/subscribe?origin=login')
    except Exception as e:
        log.error("Encountered error in callback ({}: {})".format(
            type(e).__name__, e))
        return redirect('/login')


@app.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    if 'fp' not in request.args:
        return render_template(
            'fingerprint.html',
            origin=request.args.get('origin')
        )
    fp = request.args['fp']
    con = sqlite3.connect(
        'oauth2.db',
        detect_types=sqlite3.PARSE_DECLTYPES
    )
    cur = con.cursor()
    cur.execute(
        'SELECT oauth2_token, oauth2_state, user_ids '
        'FROM fingerprints '
        'WHERE fingerprint = ?',
        (fp,)
    )
    fp_dict = cur.fetchone()
    if session.get('oauth2_token') is not None:
        token = session.get('oauth2_token')
    elif fp_dict is not None and fp_dict[0] is not None:
        token = json.loads(fp_dict[0])
    else:
        con.close()
        log.error("No token, redirecting to login")
        return redirect('/login')
    try:
        discord = make_session(token=token)
        user = discord.get(app.config['API_BASE_URL'] + '/users/@me').json()
        guilds = discord.get(
            app.config['API_BASE_URL'] + '/users/@me/guilds').json()
    except Exception as e:
        log.error("Encountered error in making session ({}: {})".format(
            type(e).__name__, e))
        return redirect('/login')
    if user.get('code') == 0 or type(guilds) == dict:
        return redirect('/login')
    user_ids = []
    if session.get('user_ids') is not None:
        user_ids += session.get('user_ids')
    if fp_dict is not None and fp_dict[2] is not None:
        user_ids += json.loads(fp_dict[2])
    user_ids = list(set(user_ids))
    device_status = None
    if len(user_ids) == 0:
        user_ids = [user['id']]
    elif user['id'] not in user_ids:
        user_ids.append(user['id'])
        device_status = 'shared'
    session['user_ids'] = user_ids
    if fp_dict is None:
        cur.execute(
            'INSERT INTO fingerprints '
            '(fingerprint, user_ids, oauth2_state, oauth2_token) '
            'VALUES (?, ?, ?, ?)',
            (
                fp, json.dumps(user_ids), session.get('oauth2_state'),
                json.dumps(session.get('oauth2_token'))
            )
        )
        log.info("New fingerprint found, storing cookie")
        con.commit()
    elif (session.get('user_ids') != json.loads(fp_dict[0]) or
          session.get('oauth2_state') != fp_dict[1] or
          session.get('oauth2_token') != json.loads(fp_dict[2])):
        cur.execute(
            'UPDATE fingerprints '
            'SET user_ids = ?, oauth2_state = ?, oauth2_token = ? '
            'WHERE fingerprint = ?',
            (
                json.dumps(user_ids), session.get('oauth2_state'),
                json.dumps(session.get('oauth2_token')), fp
            )
        )
        log.info('Updated fingerprint')
        con.commit()
    username = '{}#{}'.format(user['username'], user['discriminator'])
    user_guilds = {}
    for guild in guilds:
        user_guilds[guild['id']] = guild['name']
    shared_ids = list(session['user_ids'])
    shared_ids.remove(user['id'])
    user_shared_devices = {}
    for user_id in shared_ids:
        cur.execute(
            'SELECT user, shared_devices, plan '
            'FROM userInfo '
            'WHERE discord_id = ?',
            (user_id,)
        )
        user_dict = cur.fetchone()
        user_shared_devices[user_id] = user_dict[0]
        if user['id'] not in json.loads(user_dict[1]):
            cur.execute(
                'UPDATE userInfo '
                'SET shared_devices = json_insert(shared_devices, ?, ?) '
                'WHERE discord_id = ?',
                ('$.{}'.format(user['id']), username, user_id)
            )
        if user_dict[2] in [None, 'Banned']:
            device_status = 'flagged'
    cur.execute(
        'SELECT shared_devices, user, guilds, plan '
        'FROM userInfo '
        'WHERE discord_id = ?',
        (user['id'],)
    )
    user_dict = cur.fetchone()
    new_user = False
    if user_dict is None:
        new_user = True
        cur.execute(
            'INSERT INTO userInfo '
            '(discord_id, user, shared_devices, guilds, last_login) '
            'VALUES (?, ?, ?, ?, ?)',
            (
                user['id'], username, json.dumps(user_shared_devices),
                json.dumps(user_guilds), datetime.now().replace(microsecond=0)
            )
        )
        new_guilds = list(user_guilds.values())
        log.info("Added user info for {}".format(username))
    else:
        shared_devices = json.loads(user_dict[0])
        shared_devices.update(user_shared_devices)
        cur.execute(
            'UPDATE userInfo '
            'SET user = ?, shared_devices = ?, guilds = ?, last_login = ? '
            'WHERE discord_id = ?',
            (
                username, json.dumps(shared_devices), json.dumps(user_guilds),
                datetime.now().replace(microsecond=0), user['id']
            )
        )
        if user_dict[1] != username:
            cur.execute(
                'UPDATE userInfo '
                'SET shared_devices = json_replace(shared_devices, ?, ?) '
                'WHERE json_extract(shared_devices, ?) IS NOT NULL',
                (
                    '$.{}'.format(user['id']), username,
                    '$.{}'.format(user['id'])
                )
            )
        old_guilds = json.loads(user_dict[2])
        new_guilds = []
        for guild_id in user_guilds:
            if guild_id not in old_guilds:
                new_guilds.append(user_guilds[guild_id])
        log.info('Updated user info for {}'.format(username))
    con.commit()
    if len(shared_ids) > 0 and user_dict[3] in [None, 'Banned']:
        device_status = 'flagged'
    if new_user:
        payload = {
            'name': username,
            'discord_id': user['id'],
            'guilds': new_guilds,
            'event': 'new_user'
        }
        for queue in queues:
            queue.put(payload)
            queue.join()
    elif user_dict[3] == 'Banned':
        payload = {
            'name': username,
            'discord_id': user['id'],
            'event': 'banned'
        }
        for queue in queues:
            queue.put(payload)
            queue.join()
    if not new_user and len(new_guilds) > 0:
        payload = {
            'name': username,
            'discord_id': user['id'],
            'new_guilds': new_guilds,
            'event': 'new_guilds'
        }
        for queue in queues:
            queue.put(payload)
            queue.join()
    if device_status == 'shared':
        payload = {
            'name': username,
            'discord_id': user['id'],
            'shared_with': user_shared_devices.values(),
            'event': 'shared_device'
        }
        for queue in queues:
            queue.put(payload)
            queue.join()
    elif device_status == 'flagged':
        payload = {
            'name': username,
            'discord_id': user['id'],
            'shared_with': user_shared_devices.values(),
            'event': 'flagged_device'
        }
        for queue in queues:
            queue.put(payload)
            queue.join()
    try:
        if (request.args.get('origin') in ['login', 'map'] and
                not new_user and
                user_dict[3] == app.config['premium_role']):
            if request.headers["X-Forwarded-For"]:
                ip = request.headers["X-Forwarded-For"].split(',')[0]
            else:
                ip = request.remote_addr.split(',')[0]
            cur.execute(
                "DELETE FROM authorized "
                "WHERE DATETIME(timestamp) < DATETIME('now', '-30 seconds')"
            )
            cur.execute(
                'INSERT INTO authorized (user, ip, timestamp) '
                'VALUES (?, ?, ?)',
                (username, ip, str(datetime.utcnow().replace(microsecond=0)))
            )
            con.commit()
            con.close()
            if ('lon' not in request.args or
                    'static' not in request.args['lon']):
                log.info("{} logged into the map!".format(username))
            if 'lat' in request.args and 'lon' in request.args:
                return redirect('/?lat={}&lon={}'.format(
                    request.args['lat'], request.args['lon']))
            else:
                return redirect('/')
        elif (request.args.get('origin') != 'login' and
              not new_user and
              user_dict[3] != app.config['premium_role']):
            con.close()
            return redirect('/login')
        elif not new_user and user_dict[3] == 'Banned':
            con.close()
            return render_template('yellowjacket.html')
        elif new_user or user_dict[3] is None:
            con.close()
            log.info("Directed {} to invite page.".format(username))
            discord.post((app.config['API_BASE_URL'] + '/invites/{}').format(
                app.config['invite_code']))
            return redirect('https://discordapp.com/channels/@me')
        con.close()
        log.info("Directed {} to subscription page.".format(username))
        msg = ''
        amt = app.config['premium_price']
        if 'amount' in request.args:
            amount = request.args['amount'].replace('$', '').replace(',', '')
            try:
                amount = round(float(amount) * 100)
                if amount < 50:
                    msg = 'Amount must be at least $0.50.'
                else:
                    return render_template(
                        'custom_payment.html',
                        key=app.config['stripe_publishable_key'],
                        email="{} - {}".format(username, user['email']),
                        amount=amount,
                        message=request.args['message'],
                        id=user['id']
                    )
            except ValueError:
                msg = 'Please enter a valid amount in USD ($).'
        return render_template(
            'subscribe.html',
            key=app.config['stripe_publishable_key'],
            email="{} - {}".format(username, user['email']),
            msg=msg,
            id=user['id'],
            amt=amt,
            fp=fp
        )
    except Exception as e:
        log.error("{} encountered error ({}: {})".format(
            user['username'], type(e).__name__, e))
        return redirect('/login')


@app.route('/subscribe/success', methods=['POST'])
def success():
    user = request.form['stripeEmail'].split(' - ')[0]
    if request.args['plan'] == app.config['premium_role'].lower():
        con = sqlite3.connect('oauth2.db')
        cur = con.cursor()
        cur.execute(
            'SELECT stripe_id '
            'FROM userInfo '
            'WHERE discord_id = ?',
            (request.args['id'],)
        )
        user_dict = cur.fetchone()
        if user_dict[0] is not None:
            customer = stripe.Customer.retrieve(user_dict[0])
            customer.description = "{} - {}".format(user, request.args['id'])
            customer.email = request.form[
                'stripeEmail'].split(' - ')[1]
            customer.source = request.form['stripeToken']
            customer.save()
            log.info('Updated customer info for {}'.format(user))
        else:
            customer = stripe.Customer.create(
                description="{} - {}".format(user, request.args['id']),
                email=request.form['stripeEmail'].split(' - ')[1],
                source=request.form['stripeToken'])
            log.info('Created customer: {}'.format(user))
        if len(customer.subscriptions['data']) == 0:
            try:
                stripe.Subscription.create(
                    customer=customer.id,
                    items=[{
                        'plan': app.config['premium_role'].lower()
                    }],
                )
                cur.execute(
                    'UPDATE userInfo '
                    'SET stripe_id = ?, plan = ? '
                    'WHERE discord_id = ?',
                    (
                        customer['id'], app.config['premium_role'],
                        request.args['id']
                    )
                )
                con.commit()
                log.info('Created {} subscription for {}'.format(
                    app.config['premium_role'], user))
            except stripe.error.CardError:
                con.close()
                customer.delete()
                log.error((
                    'Deleted {} since their card was declined on ' +
                    'signup'
                ).format(user))
                return 'CARD DECLINED'
            except Exception as e:
                con.close()
                customer.delete()
                log.error((
                    'Deleted {} since there was an error while ' +
                    'processing their card on signup'
                ).format(user))
                log.error("{} encountered error ({}: {})".format(
                    user, type(e).__name__, e))
                return (
                    'SOME ERROR HAPPENED, PLEASE TRY AGAIN OR ' +
                    'CONTACT AN ADMINISTRATOR'
                )
        else:
            subscription = stripe.Subscription.retrieve(
                customer.subscriptions['data'][0]['id'])
            stripe.Subscription.modify(
                customer.subscriptions['data'][0]['id'],
                items=[{
                    'id': subscription['items']['data'][0].id
                }],
                cancel_at_period_end=False
            )
            log.info('Updated subscription for {}'.format(user))
        if request.headers["X-Forwarded-For"]:
            ip = request.headers["X-Forwarded-For"].split(',')[0]
        else:
            ip = request.remote_addr.split(',')[0]
        cur.execute(
            "DELETE FROM authorized "
            "WHERE DATETIME(timestamp) < DATETIME('now', '-30 seconds')"
        )
        cur.execute(
            'INSERT INTO authorized (user, ip, timestamp) '
            'VALUES (?, ?, ?)',
            (user, ip, str(datetime.utcnow().replace(microsecond=0)))
        )
        con.commit()
        con.close()
        if 'lon' not in request.args or 'static' not in request.args['lon']:
            log.info("{} logged into the map!".format(user))
        if 'lat' in request.args and 'lon' in request.args:
            return redirect('/?lat={}&lon={}'.format(
                request.args['lat'], request.args['lon']))
        else:
            return redirect('/')
    elif request.args['plan'] == 'charge':
        try:
            stripe.Charge.create(
                amount=request.args['amount'],
                currency='usd',
                description="{} - {}".format(user, request.args['id']),
                metadata={'message': request.args['message']},
                receipt_email=request.form['stripeEmail'].split(' - ')[1],
                source=request.form['stripeToken'],
                statement_descriptor=app.config['statement_descriptor']
            )
            log.info('Processed new tip for {}.'.format(user))
        except stripe.error.CardError:
            log.error("{}'s card declined".format(user))
            return 'CARD DECLINED'
        except Exception as e:
            log.error("{} encountered error ({}: {})".format(
                user, type(e).__name__, e))
            return (
                'SOME ERROR HAPPENED, PLEASE TRY AGAIN OR CONTACT AN ' +
                'ADMINISTRATOR'
            )
    return redirect('https://discordapp.com/channels/@me')


@app.route('/subscribe/unsubscribed', methods=['POST'])
def unsubscribed():
    con = sqlite3.connect('oauth2.db')
    cur = con.cursor()
    cur.execute(
        'SELECT stripe_id '
        'FROM userInfo '
        'WHERE discord_id = ?',
        (request.args['id'],)
    )
    user_dict = cur.fetchone()
    con.close()
    if user_dict is not None and user_dict[0] is not None:
        customer = stripe.Customer.retrieve(user_dict[0])
        subscription = stripe.Subscription.retrieve(
            customer.subscriptions['data'][0]['id'])
        if subscription.cancel_at_period_end is False:
            subscription.delete(at_period_end=True)
            log.info('Canceled subscription ({}) for {}'.format(
                subscription.id, customer.id))
    return render_template('unsubscribed.html')


@app.route('/subscribe/webhooks', methods=['POST'])
def webhooks():
    payload = request.data.decode('utf-8')
    received_sig = request.headers.get('Stripe-Signature', None)
    try:
        event = stripe.Webhook.construct_event(
            payload, received_sig, app.config['stripe_webhook_key']
        )
    except ValueError:
        log.error('Error while decoding event!')
        return 'Bad payload', 400
    except stripe.error.SignatureVerificationError:
        log.error('Invalid signature!')
        return 'Bad signature', 400
    if event.type == 'charge.succeeded':
        payload = {
            'event': event.type,
            'amount': event.data['object']['amount']
        }
        if event.data['object']['customer'] is not None:
            customer = stripe.Customer.retrieve(
                event.data['object']['customer'])
            payload['discord_id'] = customer['description'].split(' - ')[1]
        else:
            payload['discord_id'] = event.data['object'][
                'description'].split(' - ')[1]
            if 'message' in event.data['object']['metadata']:
                payload['message'] = event.data['object']['metadata'][
                    'message']
            else:
                payload['message'] = 'None'
    elif event.type == 'customer.subscription.created':
        customer = stripe.Customer.retrieve(
            event.data['object']['customer'])
        product = stripe.Product.retrieve(
            event.data['object']['plan']['product'])
        payload = {
            'event': event.type,
            'discord_id': customer['description'].split(' - ')[1],
            'plan': product['name']
        }
    elif event.type == 'customer.subscription.deleted':
        try:
            customer = stripe.Customer.retrieve(
                event.data['object']['customer'])
            product = stripe.Product.retrieve(
                event.data['object']['plan']['product'])
            payload = {
                'event': event.type,
                'discord_id': customer['description'].split(' - ')[1],
                'plan': product['name']
            }
            customer.delete()
            con = sqlite3.connect('oauth2.db')
            cur = con.cursor()
            cur.execute(
                'UPDATE userInfo '
                'SET stripe_id = ? '
                'WHERE discord_id = ?',
                (None, payload['discord_id'])
            )
            con.commit()
            con.close()
        except KeyError:
            payload = None
    elif event.type == 'customer.subscription.updated':
        if event.data['previous_attributes'].get(
                'cancel_at_period_end') is not None:
            customer = stripe.Customer.retrieve(
                event.data['object']['customer'])
            product = stripe.Product.retrieve(
                event.data['object']['plan']['product'])
            payload = {
                'event': event.type,
                'discord_id': customer['description'].split(' - ')[1],
                'plan': product['name']
            }
            if event.data['object']['cancel_at_period_end'] is True:
                payload['type'] = 'canceled'
            else:
                payload['type'] = 'reactivated'
        else:
            payload = None
    elif event.type == 'customer.updated':
        customer = stripe.Customer.retrieve(event.data['object']['id'])
        payload = {
            'event': event.type,
            'discord_id': customer['description'].split(' - ')[1]
        }
        if 'default_source' in event.data['previous_attributes']:
            source = event.data['object']['sources']['data'][0]
            payload['last4'] = source['last4']
            payload['exp_month'] = source['exp_month']
            payload['exp_year'] = source['exp_year']
            payload['brand'] = source['brand']
            payload['zip'] = source['address_zip']
        if 'email' in event.data['previous_attributes']:
            payload['old_email'] = event.data['previous_attributes'][
                'email']
            payload['email'] = event.data['object']['email']
        if ('default_source' not in event.data['previous_attributes'] and
                'email' not in event.data['previous_attributes']):
            payload = None
    elif event.type == 'invoice.payment_failed':
        customer = stripe.Customer.retrieve(
            event.data['object']['customer'])
        payload = {
            'event': event.type,
            'discord_id': customer['description'].split(' - ')[1],
            'amount': event.data['object']['amount_due'],
            'attempt': event.data['object']['attempt_count'],
            'next_attempt': event.data['object']['next_payment_attempt']
        }
    elif event.type == 'invoice.upcoming':
        customer = stripe.Customer.retrieve(
            event.data['object']['customer'])
        payload = {
            'event': event.type,
            'discord_id': customer['description'].split(' - ')[1],
            'amount': event.data['object']['amount_due']
        }
    if payload is not None:
        for queue in queues:
            queue.put(payload)
            queue.join()
    log.info('Received event: id={id}, type={type}'.format(
        id=event.id, type=event.type))
    return '', 200


def start_server():
    con = sqlite3.connect('oauth2.db')
    cur = con.cursor()
    cur.execute(
        'CREATE TABLE IF NOT EXISTS userInfo(discord_id TEXT, user TEXT, '
        'stripe_id TEXT, plan TEXT, shared_devices JSON, guilds JSON, '
        'last_login TIMESTAMP)'
    )
    cur.execute(
        'CREATE TABLE IF NOT EXISTS fingerprints(fingerprint TEXT, '
        'user_ids JSON, oauth2_state TEXT, oauth2_token JSON)'
    )
    cur.execute(
        'CREATE TABLE IF NOT EXISTS authorized(user TEXT, ip TEXT, '
        'timestamp TEXT)'
    )
    parse_settings(con, cur)
    con.close()


def parse_settings(con, cur):
    logging.getLogger("stripe").setLevel(logging.WARNING)
    logging.getLogger("discord").setLevel(logging.WARNING)
    config_files = [
        os.path.join(os.path.dirname(__file__), 'config/config.ini')
    ]
    if '-cf' in sys.argv or '--config' in sys.argv:
        config_files = []
    parser = configargparse.ArgParser(default_config_files=config_files)
    parser.add_argument(
        '-cf', '--config',
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
        '-B', '--bot_name',
        type=str,
        action='append',
        default=[],
        help='Names of Bot processes to start.'
    )
    parser.add_argument(
        '-pr', '--premium_role',
        type=str,
        required=True
    )
    parser.add_argument(
        '-sr', '--standard_role',
        type=str,
        required=True
    )
    parser.add_argument(
        '-pp', '--premium_price',
        type=int,
        required=True
    )
    parser.add_argument(
        '-stripe', '--stripe_channels',
        type=int,
        action='append',
        default=[]
    )
    parser.add_argument(
        '-uic', '--user_info_channels',
        type=int,
        action='append',
        default=[]
    )
    parser.add_argument(
        '-sd', '--statement_descriptor',
        type=str,
        required=True
    )
    parser.add_argument(
        '-inv', '--invite_code',
        type=str,
        required=True
    )
    parser.add_argument('--timeout', type=int)
    parser.add_argument('--bind', type=str)
    parser.add_argument('wsgi:app', type=str)
    args = parser.parse_args()
    api_base_url = os.environ.get(
        'API_BASE_URL', 'https://discordapp.com/api')
    app.config.update(
        premium_role=args.premium_role,
        standard_role=args.standard_role,
        premium_price=args.premium_price,
        statement_descriptor=args.statement_descriptor,
        invite_code=args.invite_code,
        OAUTH2_CLIENT_ID=args.OAUTH2_CLIENT_ID,
        SECRET_KEY=args.OAUTH2_CLIENT_SECRET,
        OAUTH2_REDIRECT_URI=args.OAUTH2_REDIRECT_URI,
        API_BASE_URL=api_base_url,
        AUTHORIZATION_BASE_URL=api_base_url + '/oauth2/authorize',
        TOKEN_URL=api_base_url + '/oauth2/token',
        stripe_secret_key=args.STRIPE_SECRET_KEY,
        stripe_publishable_key=args.STRIPE_PUBLISHABLE_KEY,
        stripe_webhook_key=args.STRIPE_WEBHOOK_KEY,
    )
    if 'http://' in app.config['OAUTH2_REDIRECT_URI']:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'
    stripe.api_key = app.config['stripe_secret_key']
    customers = stripe.Customer.list(limit=100)
    for customer in customers.auto_paging_iter():
        if len(customer['subscriptions']['data']) < 1:
            log.info('Deleted {} since they had no subscriptions'.format(
                customer.description))
            cur.execute(
                'UPDATE userInfo '
                'SET stripe_id = ? '
                'WHERE stripe_id = ?',
                (None, customer['id'])
            )
            customer.delete()
        else:
            user = customer['description'].split(' - ')[0]
            discord_id = customer['description'].split(' - ')[1]
            product = stripe.Product.retrieve(
                customer['subscriptions']['data'][0]['plan']['product'])
            cur.execute(
                'SELECT user, stripe_id, plan '
                'FROM userInfo '
                'WHERE discord_id = ?',
                (discord_id,)
            )
            user_dict = cur.fetchone()
            if user_dict is None:
                cur.execute(
                    'INSERT INTO userInfo '
                    '(discord_id, user, stripe_id, plan, shared_devices, '
                    'guilds) '
                    'VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        discord_id, user, customer['id'], product['name'],
                        json.dumps({}), json.dumps({})
                    )
                )
                log.info("Added {}'s user info".format(user))
            elif (user_dict[1] != customer['id'] or
                    user_dict[2] != product['name']):
                cur.execute(
                    'UPDATE userInfo '
                    'SET stripe_id = ?, plan = ? '
                    'WHERE discord_id = ?',
                    (customer['id'], product['name'], discord_id)
                )
                log.info("Updated {}'s user info".format(user))
    con.commit()
    log.info("Set up the webserver")
    while len(args.bot_name) < len(args.bot_tokens):
        b_ct = len(args.bot_name)
        args.bot_name.append("Bot_{}".format(b_ct))
    thread = Thread(target=start_bots, kwargs={
        'args': args
    })
    thread.start()


def start_bots(args):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    Entry = namedtuple('Entry', 'client event')
    for b_ct in range(len(args.bot_tokens)):
        b = Bot(
            name=args.bot_name[b_ct],
            premium_role=args.premium_role,
            standard_role=args.standard_role,
            stripe_channels=args.stripe_channels,
            user_info_channels=args.user_info_channels,
            token=args.bot_tokens[b_ct],
            loop=loop
        )
        if b.get_name() not in bots:
            bots[b.get_name()] = b
            queues.append(b.get_queue())
        else:
            log.critical(
                "Names of Bot processes must be unique (not case " +
                "sensitive)! Process will exit."
            )
            sys.exit(1)
    log.info("Starting up the Bots")
    for b_name in bots:
        bot = bots[b_name]
        entries.append(Entry(client=bot, event=asyncio.Event()))
        loop.run_until_complete(bot.login(bot.get_token()))
        loop.create_task(bot.connect())
        loop.create_task(bot.webhook())
    try:
        loop.run_until_complete(check_close(entries))
    except KeyboardInterrupt:
        loop.close()
    except Exception:
        raise Exception


async def check_close(entries):
    futures = [entry.event.wait() for entry in entries]
    await asyncio.wait(futures)


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


log.info('PokePaywall is getting ready')
start_server()
