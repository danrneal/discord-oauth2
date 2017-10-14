#!/usr/bin/python3
# -*- coding: utf-8 -*-

import logging
import stripe
import asyncio
import os
import json
from threading import Thread
from requests_oauthlib import OAuth2Session
from flask import Flask, session, redirect, request, url_for, render_template
from time import sleep
from bot import Bot
from utils import get_path, get_args

logging.basicConfig(
    format='[%(name)10.10s][%(levelname)8.8s] %(message)s',
    level=logging.INFO
)
log = logging.getLogger('Server')
logging.getLogger('stripe').setLevel(logging.ERROR)

args = get_args()

stripe_keys = {
    'secret_key': args.STRIPE_SECRET_KEY,
    'publishable_key': args.STRIPE_PUBLISHABLE_KEY,
    'webhook_key': args.STRIPE_WEBHOOK_KEY
}

stripe.api_key = stripe_keys['secret_key']

customers = stripe.Customer.all(limit=100)
for customer in customers.auto_paging_iter():
    discord_id = customer['description'].split(' - ')[1]
    if len(customer['subscriptions']['data']) < 1:
        customer.delete()
        log.info('Deleted `{}` since they had no subscriptions'.format(
            customer.id))
    else:
        if discord_id not in Bot.users:
            Bot.users[discord_id] = {'guilds': []}
        Bot.users['stripe_id'] = customer['id']
        Bot.users['plan'] = customer['subscriptions']['data'][0]['plan']['id']


def checker(token):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    client = Bot(loop=loop)
    loop.run_until_complete(client.login(token))
    loop.run_until_complete(client.connect())


for token in args.bot_tokens:
    thread = Thread(target=checker, kwargs={'token': token})
    thread.start()

OAUTH2_CLIENT_ID = args.OAUTH2_CLIENT_ID
OAUTH2_CLIENT_SECRET = args.OAUTH2_CLIENT_SECRET
OAUTH2_REDIRECT_URI = args.OAUTH2_REDIRECT_URI

API_BASE_URL = os.environ.get('API_BASE_URL', 'https://discordapp.com/api')
AUTHORIZATION_BASE_URL = API_BASE_URL + '/oauth2/authorize'
TOKEN_URL = API_BASE_URL + '/oauth2/token'

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = OAUTH2_CLIENT_SECRET

if 'http://' in OAUTH2_REDIRECT_URI:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'


def token_updater(token):
    session['oauth2_token'] = token


def make_session(token=None, state=None, scope=None):
    return OAuth2Session(
        client_id=OAUTH2_CLIENT_ID,
        token=token,
        state=state,
        scope=scope,
        redirect_uri=OAUTH2_REDIRECT_URI,
        auto_refresh_kwargs={
            'client_id': OAUTH2_CLIENT_ID,
            'client_secret': OAUTH2_CLIENT_SECRET
        },
        auto_refresh_url=TOKEN_URL,
        token_updater=token_updater
    )


@app.route('/login')
def login():
    scope = request.args.get(
        'scope',
        'identify email'
    )
    discord = make_session(scope=scope.split(' '))
    authorization_url, state = discord.authorization_url(
        AUTHORIZATION_BASE_URL)
    session['oauth2_state'] = state
    return redirect(authorization_url)


@app.route('/login/callback')
def callback():
    if request.values.get('error'):
        return request.values['error']
    discord = make_session(state=session.get('oauth2_state'))
    try:
        token = discord.fetch_token(
            TOKEN_URL,
            client_secret=OAUTH2_CLIENT_SECRET,
            authorization_response=request.url.strip()
        )
        session['oauth2_token'] = token
        return redirect(url_for('.subscribe'))
    except:
        return redirect('/login')


@app.route('/subscribe', methods=['GET'])
def subscribe():
    try:
        discord = make_session(token=session.get('oauth2_token'))
        user = discord.get(API_BASE_URL + '/users/@me').json()
    except:
        return redirect('/login')
    from_login = (request.referrer is not None and
                  request.referrer.startswith(
                      'https://discordapp.com/oauth2/authorize'))
    try:
        if (user.get('code') == 0 or
            from_login is False and
            'coupon' not in request.args and
            'amount' not in request.args and
            (user['id'] not in Bot.users or
             Bot.users[user['id']]['plan'] is None)):
            return redirect('/login')
        elif from_login is True and user['id'] not in Bot.users:
            return redirect('https://discord.gg/YU8QuQe')
        elif (('map' in request.args or
               from_login is True) and
              user['id'] in Bot.users and
              Bot.users[user['id']]['plan'] == args.premium_role):
            if request.headers["X-Forwarded-For"]:
                ip = request.headers["X-Forwarded-For"].split(',')[0]
            else:
                ip = request.remote_addr.split(',')[0]
            try:
                with open(
                        get_path('dicts/authorized.json')) as authorized_file:
                    authorized = json.load(authorized_file)
            except:
                authorized = []
            authorized.append(ip)
            with open(get_path(
                    'dicts/authorized.json'), 'w') as authorized_file:
                json.dump(authorized, authorized_file, indent=4)
            if ('lon' not in request.args or
                    'static' not in request.args['lon']):
                log.info("`{}` logged into the map!".format(user['username']))
            if 'lat' in request.args and 'lon' in request.args:
                return redirect('/?lat={}&lon={}'.format(
                    request.args['lat'], request.args['lon']))
            else:
                return redirect('/')
        else:
            msg = ''
            coupon = None
            amt1 = args.standard_price
            amt2 = args.premium_price
            if 'amount' in request.args:
                amount = request.args['amount'].replace('$', '').replace(
                    ',', '')
                try:
                    amount = round(float(amount) * 100)
                    if amount < 50:
                        msg = 'Amount must be at least $0.50.'
                    elif ('area' not in request.args or
                          request.args['area'] == ''):
                        msg = 'Please enter an area request.'
                    else:
                        return render_template(
                            'custom_payment.html',
                            key=stripe_keys['publishable_key'],
                            email=user['username'] + ' - ' + user['email'],
                            amount=amount,
                            area=request.args['area'],
                            id=user['id']
                        )
                except:
                    msg = 'Please enter a valid amount in USD ($).'
            if 'coupon' in request.args:
                try:
                    coupon = stripe.Coupon.retrieve(request.args['coupon'])
                    if coupon['valid'] is not True:
                        raise Exception
                    elif coupon['amount_off'] is not None:
                        discount = '${:,.2f}'.format(
                            coupon['amount_off'] / 100)
                        amt1 = amt1 - coupon['amount_off']
                        amt2 = amt2 - coupon['amount_off']
                    else:
                        discount = str(coupon['percent_off']) + '%'
                        amt1 = round(amt1 - amt1 * (
                            coupon['percent_off'] / 100))
                        amt2 = round(amt2 - amt2 * (
                            coupon['percent_off'] / 100))
                    if coupon['duration'] == 'forever':
                        months = 'the duration of your subscription'
                    elif coupon['duration'] == 'once':
                        months = '(1) month'
                    else:
                        months = (
                            '(' + str(coupon['duration_in_months']) +
                            ') months'
                        )
                    msg = (
                        'Coupon applied!  You will receive ' + discount +
                        ' off for ' + months + '.'
                    )
                    coupon = request.args['coupon']
                    log.info('Coupon found for `{}`, `{}`, `{}`'.format(
                        user['username'], discount, months))
                except:
                    msg = 'Coupon code is not valid or expired.'
            return render_template(
                'subscribe.html',
                key=stripe_keys['publishable_key'],
                email=user['username'] + ' - ' + user['email'],
                msg=msg,
                id=user['id'],
                amt1=amt1,
                amt2=amt2,
                coupon=coupon
            )
    except:
        try:
            with open(get_path('dicts/errors.json')) as error_file:
                errors = json.load(error_file)
        except:
            errors = []
        errors.append(user)
        with open(get_path('dicts/errors.json'), 'w') as error_file:
            json.dump(errors, error_file, indent=4)
        return redirect('/login')


@app.route('/subscribe/success', methods=['POST'])
def success():
    if request.args['plan'] != 'charge':
        if (request.args['id'] in Bot.users and
                Bot.users[request.args['id']]['stripe_id'] is not None):
            customer = stripe.Customer.retrieve(
                Bot.users[request.args['id']]['stripe_id'])
            customer.description = (
                request.form['stripeEmail'].split(' - ')[0] + ' - ' +
                request.args['id']
            )
            customer.email = request.form['stripeEmail'].split(' - ')[1]
            customer.source = request.form['stripeToken']
            customer.save()
            log.info('Updated customer info for `{}`'.format(customer.id))
        else:
            customer = stripe.Customer.create(
                description=(
                    request.form['stripeEmail'].split(' - ')[0] + ' - ' +
                    request.args['id']
                ),
                email=request.form['stripeEmail'].split(' - ')[1],
                source=request.form['stripeToken'])
            log.info('Created customer: `{}`'.format(customer.id))
        if request.args['id'] not in Bot.users:
            Bot.users[request.args['id']] = {'guilds': []}
        Bot.users[request.args['id']]['stripe_id'] = customer['id']
        if request.args['coupon'] == 'None':
            coupon = None
        else:
            coupon = request.args['coupon']
    if request.args['plan'] == args.standard_role:
        if len(customer.subscriptions['data']) > 0:
            subscription = stripe.Subscription.retrieve(
                customer.subscriptions['data'][0]['id'])
            item_id = subscription['items']['data'][0].id
            if (subscription['plan']['id'] == args.premium_role or
                    coupon is not None):
                stripe.Subscription.modify(
                    customer.subscriptions['data'][0]['id'],
                    items=[{
                        'id': item_id,
                        'plan': args.standard_role
                    }],
                    prorate=False,
                    coupon=coupon
                )
                log.info('Modified `{}` subscription (`{}`) for `{}`'.format(
                    args.standard_role, subscription.id, customer.id))
        else:
            try:
                stripe.Subscription.create(
                    customer=customer.id,
                    items=[{
                        'plan': args.standard_role
                    }],
                    coupon=coupon
                )
                log.info('Created `{}` subscription for `{}`'.format(
                    args.standard_role, customer.id))
            except stripe.error.CardError as e:
                customer.delete()
                Bot.users[request.args['id']]['stripe_id'] = None
                if len(Bot.users[request.args['id']]['guilds']) == 0:
                    Bot.users.pop(request.args['id'])
                log.info((
                    'Deleted `{}` since their card was declined on signup'
                ).format(customer.id))
                return 'CARD DECLINED'
            except:
                customer.delete()
                Bot.users[request.args['id']]['stripe_id'] = None
                if len(Bot.users[request.args['id']]['guilds']) == 0:
                    Bot.users.pop(request.args['id'])
                log.info((
                    'Deleted `{}` since there was an error while processing ' +
                    'their card on signup'
                ).format(customer.id))
                return (
                    'SOME ERROR HAPPENED, PLEASE TRY AGAIN OR CONTACT AN ' +
                    'ADMINISTRATOR'
                )
        Bot.users[request.args['id']]['plan'] = args.standard_role
    elif request.args['plan'] == args.premium_role:
        if len(customer.subscriptions['data']) > 0:
            subscription = stripe.Subscription.retrieve(
                customer.subscriptions['data'][0]['id'])
            item_id = subscription['items']['data'][0].id
            if (subscription['plan']['id'] == args.standard_role or
                    coupon is not None):
                stripe.Subscription.modify(
                    customer.subscriptions['data'][0]['id'],
                    items=[{
                        'id': item_id,
                        'plan': args.premium_role
                    }],
                    coupon=coupon
                )
                log.info('Modified `{}` subscription (`{}`) for `{}`'.format(
                    args.premium_role, subscription.id, customer.id))
        else:
            try:
                stripe.Subscription.create(
                    customer=customer.id,
                    items=[{
                        'plan': args.premium_role
                        }],
                    coupon=coupon
                )
                log.info('Created `{}` subscription for `{}`'.format(
                    args.premium_role, customer.id))
            except stripe.error.CardError as e:
                customer.delete()
                Bot.users[request.args['id']]['stripe_id'] = None
                if len(Bot.users[request.args['id']]['guilds']) == 0:
                    Bot.users.pop(request.args['id'])
                log.info((
                    'Deleted `{}` since their card was declined on signup'
                ).format(customer.id))
                return 'CARD DECLINED'
            except:
                customer.delete()
                Bot.users[request.args['id']]['stripe_id'] = None
                if len(Bot.users[request.args['id']]['guilds']) == 0:
                    Bot.users.pop(request.args['id'])
                log.info((
                    'Deleted `{}` since there was an error while processing ' +
                    'their card on signup'
                ).format(customer.id))
                return (
                    'SOME ERROR HAPPENED, PLEASE TRY AGAIN OR CONTACT AN ' +
                    'ADMINISTRATOR'
                )
        Bot.users[request.args['id']]['plan'] = args.premium_role
        if request.headers["X-Forwarded-For"]:
            ip = request.headers["X-Forwarded-For"].split(',')[0]
        else:
            ip = request.remote_addr.split(',')[0]
        try:
            with open(get_path(
                    'dicts/authorized.json')) as authorized_file:
                authorized = json.load(authorized_file)
        except:
            authorized = []
        authorized.append(ip)
        with open(get_path(
                'dicts/authorized.json'), 'w') as authorized_file:
            json.dump(authorized, authorized_file, indent=4)
        if ('lon' not in request.args or
                'static' not in request.args['lon']):
            log.info("`{}` logged into the map!".format(
                request.form['stripeEmail'].split(' - ')[0]))
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
                description=(
                    request.form['stripeEmail'].split(' - ')[0] + ' - ' +
                    request.args['id']
                ),
                metadata={'area': request.args['area']},
                receipt_email=request.form['stripeEmail'].split(' - ')[1],
                source=request.form['stripeToken'],
                statement_descriptor=args.statement_descriptor
            )
            log.info((
                'Processed new area request for `{}` for the `{}`area.'
                ).format(
                    request.form['stripeEmail'].split(' - ')[0],
                    request.args['area']
                ))
        except stripe.error.CardError as e:
            return 'CARD DECLINED'
        except:
            return (
                'SOME ERROR HAPPENED, PLEASE TRY AGAIN OR CONTACT AN ' +
                'ADMINISTRATOR'
            )


@app.route('/subscribe/unsubscribed', methods=['POST'])
def unsubscribed():
    if (request.args['id'] in Bot.users and
            Bot.users[request.args['id']]['stripe_id'] is not None):
        customer = stripe.Customer.retrieve(
            Bot.users[request.args['id']]['stripe_id'])
        subscription = stripe.Subscription.retrieve(
            customer.subscriptions['data'][0]['id'])
        if subscription.cancel_at_period_end is False:
            subscription.delete(at_period_end=True)
            log.info('Canceled subscription (`{}`) for `{}`'.format(
                subscription.id, customer.id))
    return render_template('unsubscribed.html')


@app.route('/subscribe/webhooks', methods=['POST'])
def webhooks():
    payload = request.data.decode('utf-8')
    received_sig = request.headers.get('Stripe-Signature', None)
    try:
        event = stripe.Webhook.construct_event(
            payload, received_sig, stripe_keys['webhook_key']
        )
    except ValueError:
        log.info('Error while decoding event!')
        return ('Bad payload', 400)
    except stripe.error.SignatureVerificationError:
        log.info('Invalid signature!')
        return ('Bad signature', 400)
    delete = False
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
            payload['discord_id'] = event.data['object']['description'].split(
                ' - ')[1]
            payload['area'] = event.data['object']['metadata']['area']
    elif (event.type == 'customer.discount.created' or
          event.type == 'customer.discount.updated'):
        customer = stripe.Customer.retrieve(event.data['object']['customer'])
        payload = {
            'event': event.type,
            'discord_id': customer['description'].split(' - ')[1],
            'coupon': event.data['object']['coupon']['id']
        }
        if event.data['object']['coupon']['amount_off'] is not None:
            payload['discount'] = '-${:,.2f}'.format(
                event.data['object']['coupon']['amount_off'] / 100)
        else:
            payload['discount'] = str(event.data['object']['coupon'][
                'percent_off']) + '% off'
        if event.data['object']['coupon']['duration'] == 'forever':
            payload['duration'] = 'The duration of your subscription'
        elif event.data['object']['coupon']['duration'] == 'once':
            payload['duration'] = '1 month'
        else:
            payload['duration'] = str(event.data['object']['coupon'][
                'duration_in_months']) + ' months'
    elif event.type == 'customer.subscription.created':
        customer = stripe.Customer.retrieve(event.data['object']['customer'])
        payload = {
            'event': event.type,
            'discord_id': customer['description'].split(' - ')[1],
            'plan': event.data['object']['plan']['name']
        }
    elif event.type == 'customer.subscription.deleted':
        customer = stripe.Customer.retrieve(event.data['object']['customer'])
        payload = {
            'event': event.type,
            'discord_id': customer['description'].split(' - ')[1],
            'plan': event.data['object']['plan']['name']
        }
        customer.delete()
        Bot.users[payload['discord_id']]['plan'] = None
        delete = True
    elif event.type == 'customer.subscription.updated':
        customer = stripe.Customer.retrieve(event.data['object']['customer'])
        payload = {
            'event': event.type,
            'discord_id': customer['description'].split(' - ')[1],
            'plan': event.data['object']['plan']['name']
        }
        if event.data['object']['cancel_at_period_end'] is True:
            payload['type'] = 'canceled'
        elif payload['plan'] != event.data['previous_attributes']['plan'][
                'name']:
            payload['old_plan'] = event.data['previous_attributes']['plan'][
                'name']
            if payload['plan'].lower() == args.premium_role:
                payload['type'] = 'upgraded'
            else:
                payload['type'] = 'downgraded'
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
            payload['old_email'] = event.data['previous_attributes']['email']
            payload['email'] = event.data['object']['email']
        if ('default_source' not in event.data['previous_attributes'] and
                'email' not in event.data['previous_attributes']):
            payload = None
    elif event.type == 'invoice.payment_failed':
        customer = stripe.Customer.retrieve(event.data['object']['customer'])
        payload = {
            'event': event.type,
            'discord_id': customer['description'].split(' - ')[1],
            'amount': event.data['object']['amount_due'],
            'attempt': event.data['object']['attempt_count'],
            'next_attempt': event.data['object']['next_payment_attempt']
        }
    elif event.type == 'invoice.upcoming':
        customer = stripe.Customer.retrieve(event.data['object']['customer'])
        payload = {
            'event': event.type,
            'discord_id': customer['description'].split(' - ')[1],
            'amount': event.data['object']['amount_due']
        }
    if (payload is not None and
            payload['discord_id'] in Bot.users):
        for guild in Bot.users[payload['discord_id']]['guilds']:
            count = 0
            while count <= 6:
                if guild in Bot.guilds:
                    Bot.guilds[guild]['q'].put(payload)
                    Bot.guilds[guild]['q'].join()
                    payload['sent'] = True
                    break
                else:
                    sleep(5)
                    count += 1
    if delete is True:
        Bot.users[payload['discord_id']]['stripe_id'] = None
    log.info('Received event: id={id}, type={type}'.format(
        id=event.id, type=event.type))
    return ('', 200)


if __name__ == '__main__':
    app.run()
