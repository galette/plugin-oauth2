<?php

/**
 * Copyright © 2021-2024 The Galette Team
 *
 * This file is part of Galette OAuth2 plugin (https://galette-community.github.io/plugin-oauth2/).
 *
 * Galette is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Galette is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Galette OAuth2 plugin. If not, see <http://www.gnu.org/licenses/>.
 */

declare(strict_types=1);

namespace GaletteOAuth2\Authorization;

use DI\Container;
use Galette\Core\Db;
use Galette\Core\Login;
use Galette\Entity\Adherent;
use Galette\Entity\Social;
use GaletteOAuth2\Tools\Config;
use GaletteOAuth2\Tools\Debug;

/**
 * Helpers for user authorization
 *
 * @author Manuel Hervouet <manuelh78dev@ik.me>
 * @author Johan Cwiklinski <johan@x-tnd.be>
 */
final class UserHelper
{
    public static function login(Container $container, $nick, $password): int|false
    {
        $preferences = $container->get('preferences');
        /** @var Login $login */
        $login = $container->get('login');
        $history = $container->get('history');
        $session = $container->get('session');
        $flash = $container->get('flash');

        if (trim($nick) === '' || trim($password) === '') {
            return false;
        }

        if ($nick === $preferences->pref_admin_login) {
            $pw_superadmin = password_verify(
                $password,
                $preferences->pref_admin_pass,
            );

            if (!$pw_superadmin) {
                $pw_superadmin = (
                    md5($password) === $preferences->pref_admin_pass
                );
            }

            if ($pw_superadmin) {
                $flash->addMessage(
                    'error_detected',
                    _T('Cannot OAuth login from superadmin account!', 'oauth2')
                );
                return false;
            }
        } else {
            $login->logIn($nick, $password);
        }

        if ($login->isLogged()) {
            $session->login = $login;
            $history->add(_T('Login'));

            return $login->id;
        }
        $history->add(_T('Authentication failed'), $nick);

        return false;
    }

    public static function logout(Container $container): void
    {
        /** @var Login $login */
        $login = $container->get('login');
        $history = $container->get('history');
        $session = $container->get('session');

        $login->logout();
        $session->login = $login;
        $history->add(_T('Logout'));
    }

    /**
     * Get user data
     *
     * @param Container    $container Container instance
     * @param int          $id        User ID
     * @param array        $options   Access options
     * @param array|string $scopes    Scopes
     * @return array
     * @throws UserAuthorizationException
     * @throws \DI\DependencyException
     * @throws \DI\NotFoundException
     * @throws \Throwable
     */
    public static function getUserData(Container $container, int $id, array $options, array|string $scopes): array
    {
        /** @var Db $zdb */
        $zdb = $container->get('zdb');

        if ($id === 0) {
            throw new UserAuthorizationException(_T('User not found.', 'oauth2'));
        }

        $member = new Adherent($zdb);
        $member->load($id);

        $default_scope = array_search('member', $scopes, true);
        if ($default_scope !== false) {
            unset($scopes[$default_scope]);
        } else {
            throw new UserAuthorizationException(
                sprintf(
                    _T('Default scope (%s) has not been authorized.', 'oauth2'),
                    'member'
                )
            );
        }

        //FIXME: I really doubt reworking names is a good idea outside a specific usage
        $nameExplode = preg_split('/[\\s,-]+/', $member->name);
        if (count($nameExplode) > 0) {
            $nameFPart = $nameExplode[0];
            //too short?
            if (mb_strlen($nameFPart) < 4 && count($nameExplode) > 1) {
                $nameFPart .= $nameExplode[1];
            }
        } else {
            $nameFPart = $member->name;
        }

        //Normalized format s.name (example mail usage : s.name@xxxx.xx )
        //FIXME: why don't use email directly?
        $norm_login = sprintf(
            '%s.%s',
            mb_substr(self::stripAccents($member->surname), 0, 1),
            self::stripAccents($nameFPart)
        );

        //TODO: rework options as documented in README.md
        //check active member ?
        if (!$member->isActive()) {
            throw new UserAuthorizationException(_T('You are not an active member.', 'oauth2'));
        }

        //check email
        if (!filter_var($member->email, FILTER_VALIDATE_EMAIL)) {
            throw new UserAuthorizationException(_T("Sorry, you can't login. Please, add an email address to your account.", 'oauth2'));
        }

        //teamonly
        if (in_array('teamonly', $options, true)) {
            if (!$member->isAdmin() && !$member->isStaff() && !$member->isGroupManager(null)) {
                throw new UserAuthorizationException(
                    _T("Sorry, you can't login because your are not a team member.", 'oauth2')
                );
            }
        }
        //uptodate
        if (in_array('uptodate', $options, true)) {
            if (!$member->isUp2Date()) {
                throw new UserAuthorizationException(
                    _T("Sorry, you can't login because your are not an up-to-date member.", 'oauth2')
                );
            }
        }

        $oauth_data = [
            'id' => $member->id,
            'identifier' => $member->id, //nextcloud
            'displayName' => $member->sname,
            'username' => $norm_login, //FIXME: $member->login,
            'userName' => $norm_login, //FIXME: $member->login,
            'name' => $norm_login, //FIXME: $member->sname,
            'email' => $member->email,
            'mail' => $member->email,
            'language' => $member->language,
            'status' => $member->status
        ];

        //member:personal
        if (in_array('member:personal', $scopes)) {
            $oauth_data['birthDate'] = $member->birthdate;
            $oauth_data['birthPlace'] = $member->birth_place;
            $oauth_data['job'] = $member->job;
            $oauth_data['gender'] = $member->gender;
            $oauth_data['gpgid'] = $member->gnupgid;
        }

        //member:localization
        if (in_array('member:localization', $scopes)) {
            $oauth_data['country'] = $member->country;
            $oauth_data['zip'] = $member->zipcode;
            $oauth_data['city'] = $member->town;
            $oauth_data['region'] = $member->region;
        }

        //member:localization:fine
        if (in_array('member:localization:fine', $scopes)) {
            $oauth_data['address'] = $member->address;
            //TODO
            /*$oauth_data['latitude'] = $member->latitude;
            $oauth_data['longitude'] = $member->longitude;*/
        }

        //member:phones
        if (in_array('member:phones', $scopes)) {
            $phone = '';
            if ($member->phone) {
                $phone = $member->phone;
            }
            if ($member->gsm) {
                if ($phone) {
                    $phone .= ' - ';
                }
                $phone .= $member->gsm;
            }
            $oauth_data['phone'] = $phone;
        }

        //member:socials
        if (in_array('member:socials', $scopes)) {
            $socials = Social::getListForMember($member->id);
            foreach ($socials as $social) {
                /** @phpstan-ignore-next-line (fixed in Galette 1.1.1) */
                $oauth_data['socials'][$social->type] = $social->url;
            }
        }

        //member:groups
        if (in_array('member:groups', $scopes)) {
            //nextcloud : set fields Groups claim (optional) = groups
            //FIXME: I don't know how nextcloud manages groups, but there are not groups...
            $oauth_data['groups'] = self::getUserGroups($member);
        }

        //member:due_date
        if (in_array('member:due_date', $scopes)) {
            $oauth_data['due_date'] = $member->due_date;
        }

        return $oauth_data;
    }

    /**
     * Comma separated groups names
     *
     * @param Adherent $member Member
     *
     * @return string
     */
    protected static function getUserGroups(Adherent $member): array
    {
        $groups = [$member->sstatus]; //first group is the member status

        if ($member->isAdmin()) {
            $groups[] = 'admin';
        }

        if ($member->isStaff()) {
            $groups[] = 'staff';
        }

        if (count($member->getManagedGroups()) > 0) {
            $groups[] = 'groupmanager';
        }

        if ($member->isUp2Date()) {
            $groups[] = 'uptodate';
        }

        //FIXME: add groups from groups table? Or another way? info_adh does not seems a good way for everyone
        //FIXME: For example, data is replaced on duplication, thus oauth groups configuration would be lost
        //FIXME: maybe should we just rely on real Galette groups.
        //Add externals groups (free text in info_adh)
        //Example #GROUPS:compta;accueil#
        if (preg_match('/#GROUPS:([^#]*([^#]*))#/mui', $member->others_infos_admin, $matches, PREG_OFFSET_CAPTURE)) {
            $g = $matches[1][0];
            Debug::log("Groups added {$g}");
            $groups = array_merge($groups, explode(';', $g));
        }

        //TODO: maybe a bit excessive for a global usage?
        //Reformat group with strtolower, remove whites & slashs
        foreach ($groups as &$group) {
            $group = trim($group);
            $group = str_replace([' ', '/', '(', ')'], ['_', '', '', ''], $group);
            $group = str_replace('__', '_', $group);
            $group = self::stripAccents($group);
        }

        return $groups;
    }

    /**
     * Get configured options
     *
     * @param Config $config Config instance
     *
     * @param string $client_id
     *
     * @return array
     */
    public static function getOptions(Config $config, string $client_id): array
    {
        $options = [];
        $o = $config->get("{$client_id}.options");

        if ($o) {
            $o = str_replace(';', ' ', $o);
            $o = explode(' ', $o);
            $options = array_merge($o, $options);
        }
        $options = array_unique($options);
        Debug::log('Options: ' . implode(';', $options));

        return $options;
    }

    /**
     * Merge requested and configured scopes
     *
     * @param Config $config Config instance
     *
     * @param string       $client_id        Client app identifier
     * @param array|string $requested_scopes Requested scopes from query string
     *
     * @return array
     */
    public static function mergeScopes(Config $config, string $client_id, array|string $requested_scopes): array
    {
        $scopes = [];
        if (!is_array($requested_scopes)) {
            $requested_scopes = str_replace([';', ','], ' ', $requested_scopes);
            $requested_scopes = explode(' ', $requested_scopes);
        }
        $scopes = array_merge($scopes, $requested_scopes);

        $conf_scopes = $config->get("{$client_id}.scopes");
        if ($conf_scopes) {
            if (!is_array($conf_scopes)) {
                $conf_scopes = str_replace([';', ','], ' ', $conf_scopes);
                $conf_scopes = explode(' ', $conf_scopes);
            }
            $scopes = array_merge($scopes, $conf_scopes);
        }
        $scopes = array_unique($scopes);
        $scopes = array_map('strtolower', $scopes);
        Debug::log('Scopes: ' . implode(';', $scopes));

        return $scopes;
    }

    // Nextcloud data:
    // \DBG = Hybridauth\User\Profile::__set_state(array(
    // 'identifier' => 3992, 'webSiteURL' => NULL, 'profileURL' => NULL,
    // 'photoURL' => NULL,
    // 'displayName' => ' TEST', 'description' => NULL, 'firstName' => NULL, 'lastName' => NULL, 'gender' => NULL,
    // 'language' => NULL,
    // 'age' => NULL, 'birthDay' => NULL, 'birthMonth' => NULL, 'birthYear' => NULL,
    // 'email' => 'uuuu@ik.me', 'emailVerified' => NULL, 'phone' => NULL,
    // 'address' => NULL, 'country' => NULL, 'region' => NULL, 'city' => NULL, 'zip' => NULL

    /**
     * Strips accented characters, lower string
     *
     * @param string $str
     * @return string
     */
    public static function stripAccents(string $str): string
    {
        return mb_strtolower(
            transliterator_transliterate(
                "Any-Latin; Latin-ASCII; [^a-zA-Z0-9\.\ -_] Remove;",
                $str
            )
        );
    }
}
