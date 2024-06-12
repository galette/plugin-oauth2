Makes Galette act as a oAuth2 server; so it is possible to use existing members to log-in on third party websites, like [Flarum](https://flarum.org/), [Nextcould](https://nextcloud.com/), and so on!

# Setup

This project use `league/oauth2-server`, `symfony/yaml` and `hassankhan/config` packages.

To automatically download these packages:
```
cd plugin-oauth2
composer install
```

# Configuration

## Prepare public/private keys

```
cd plugin-oauth2/config
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.key
chmod 660 *.key


vendor/bin/generate-defuse-key
copy-paste the hexadecimal string result in plugin-oauth2/config/encryption-key.php
```

## Configure a ClientEntity

Rename `config/config.yml.dist` to `config/config.yml` and edit according to your third party applicaiton settings:

```
global:
    password: abc123

galette_flarum:
    title: 'Forum Flarum'
    redirect_logout: 'http://192.168.1.99/flarum/public'
    options: teamonly
galette_nc:
    title: 'Nextcloud'
    redirect_logout: 'http://192.168.1.99/nextcloud'
    options: uptodate
galette_xxxxx:

```

The corresponding Flarum configuration:

![Flarum configuration example](examples/flarum.png)

The corresponding NextCloud configuration:

![Nextcloud configuration example](examples/nextcloud.png)


### Available options :

* admin: only staff members can login
* staff: only staff members can login
* uptodate: only uptodate members can login
* groupmanager: groups managers can login

### Scopes

* `member`: default, basic scope:
  * user full name,
  * login,
  * email,
  * language
  * company name if relevant
* `member:personal` precise personal data:
  * birth date,
  * job,
  * gender,
  * birth place
  * GPG id
* `member:localization` localization data:
  * country,
  * region,
  * town
  * zipcode
* `member:localization:fine` precise localization data:
  * full address,
  * coordinates (if used with maps plugin)
* `member:phones`:
  * mobile phone
  * phone
* `member:socials`:
  * all registered social networks
* `member:groups`:
  * groups member is part of
* `member:due_date`:
  * due_datee date

# Usage

## Nextcloud - how add groups for a specific member
Edit a member : In `info_adh` field you can add a line with `#GROUPS:group1;group2#`

Example :
```
#GROUPS:accouting;home#
```

# More information about OAuth2 Server
* https://oauth2.thephpleague.com/
* https://github.com/thephpleague/oauth2-server/
