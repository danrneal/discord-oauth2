# Discord-OAuth2

[![python](https://img.shields.io/badge/Python-3.6-blue.svg)]() [![license](https://img.shields.io/github/license/mashape/apistatus.svg)](https://img.shields.io/gitlab/license/dan.r.neal/discord-oauth2) [![pipeline status](https://gitlab.com/dan.r.neal/Discord-OAuth2/badges/master/pipeline.svg)](https://gitlab.com/dan.r.neal/Discord-OAuth2/commits/master) [![Discord](https://img.shields.io/discord/314040044052545538.svg)](https://discordapp.com/channels/314040044052545538/314040595456983040) [![donate](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/dneal12)

A set up to assign roles with Stripe in Discord and allow access via OAuth2. Intended for use with PMSF.

**Requirements:**

1. Ubuntu 16.04
2. Python3
3. nginx
4. A Discord bot with proper permissions.  Here is a link on how to set it up: https://github.com/reactiflux/discord-irc/wiki/Creating-a-discord-bot-&-getting-a-token

**How to install:**

1. `sudo apt-get install php-sqlite3`
2. `cd var/www/html/PMSF`
3. `git clone git@gitlab.com:alphapokes/Discord-OAuth2.git`
4. `cd ./Discord_OAuth2`
5. `python3 -m pip install virtualenv`
6. `virtualenv env`
7. `source env/bin/activate`
8. `python3 -m pip install -r requirements.txt`
9. `deactivate`

**How to set up:**

1. Rename `config.ini.example` to `config.ini` in the config folder.
2. Set all required variables in config file.
3. Set your redirect uri in your discord developer console, it should match the same value set in the config file.
4. Copy the header of `index.php` in the setup folder into your current PMSF `index.php`.
5. `sudo chown -R www-data:www-data /var/www/html/PMSF/Discord-OAuth2/`
6. Update your nginx config file in `/etc/nginx/sites-enabled` with the settings in `example.conf` in the setup folder.
7. `systemctl restart nginx`
8. Move `oauth2.service` from the setup folder to `/etc/systemd/system`.
9. `systemctl enable oauth2`

**How to run/restart:**

1. To run: `systemctl start oauth2`
2. To restart: `systemctl restart oauth2`
3. To view logs: `journalctl -u oauth2 -f`

**Credit:**

Thanks to Glennmen for [PMSF](https://github.com/Glennmen/PMSF)