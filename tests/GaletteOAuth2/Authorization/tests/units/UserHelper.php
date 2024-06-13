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

namespace GaletteOauth2\Authorization\tests\units;

use Galette\GaletteTestCase;

/**
 * UserHelper tests
 *
 * @author Johan Cwiklinski <johan@x-tnd.be>
 */
class UserHelper extends GaletteTestCase
{
    protected int $seed = 20230324120838;

    /**
     * Tear down tests
     *
     * @return void
     */
    public function tearDown(): void
    {
        parent::tearDown();

        //delete social networks
        $delete = $this->zdb->delete(\Galette\Entity\Social::TABLE);
        $this->zdb->execute($delete);

        //drop dynamic translations
        $delete = $this->zdb->delete(\Galette\Core\L10n::TABLE);
        $this->zdb->execute($delete);

        $delete = $this->zdb->delete(\Galette\Entity\Adherent::TABLE);
        $delete->where(['fingerprint' => 'FAKER' . $this->seed]);
        $this->zdb->execute($delete);
    }

    /**
     * Test stripAccents
     *
     * @return void
     */
    public function testStripAccents(): void
    {
        /** @var \Galette\Core\Plugins */
        global $plugins;

        $str = "çéè-ßØ";
        $this->assertSame('cee-sso', \GaletteOAuth2\Authorization\UserHelper::stripAccents($str));
    }

    /**
     * Test getUserData
     *
     * @return void
     */
    public function testGetUserData(): void
    {
        global $container;

        $this->initStatus();
        $adh1  = $this->getMemberOne();

        $data = $this->dataAdherentOne();
        $data['bool_admin_adh'] = true;
        $check = $this->adh->check($data, [], []);
        if (is_array($check)) {
            var_dump($check);
        }
        $this->assertTrue($check);

        $store = $this->adh->store();
        $this->assertTrue($store);

        //test for default scope
        $user_data = \GaletteOAuth2\Authorization\UserHelper::getUserData(
            $container,
            $adh1->id,
            [],
            ['member']
        );

        $expected_base = [
            'id' => $adh1->id,
            'sub' => $adh1->id,
            'identifier' => $adh1->id,
            'name' => $adh1->sfullname,
            'displayName' => $adh1->sname,
            'username' => 'r.durand',
            'userName' => 'r.durand',
            'email' => $adh1->email,
            'mail' => $adh1->email,
            'locale' => $adh1->language,
            'language' => $adh1->language,
            'status' => $adh1->status,
        ];

        $this->assertSame(
            $expected_base,
            $user_data
        );

        //test personal scope
        $user_data = \GaletteOAuth2\Authorization\UserHelper::getUserData(
            $container,
            $adh1->id,
            [],
            ['member', 'member:personal']
        );

        $this->assertSame(
            $expected_base + [
                'birthdate' => '1941-12-26',
                'birthplace' => 'Gonzalez-sur-Meunier',
                'job' => 'Chef de fabrication',
                'gender' => 'Unspecified',
                'gpgid' => ''
            ],
            $user_data
        );

        //test phones scope
        $user_data = \GaletteOAuth2\Authorization\UserHelper::getUserData(
            $container,
            $adh1->id,
            [],
            ['member', 'member:phones']
        );

        $this->assertSame(
            $expected_base + ['phone' => '0439153432'],
            $user_data
        );

        //test groups scope
        $user_data = \GaletteOAuth2\Authorization\UserHelper::getUserData(
            $container,
            $adh1->id,
            [],
            ['member', 'member:groups']
        );

        $this->assertSame(
            $expected_base + [
                'groups' => [
                    'non-member',
                    'admin'
                ]
            ],
            $user_data
        );

        $user_data = \GaletteOAuth2\Authorization\UserHelper::getUserData(
            $container,
            $adh1->id,
            ['teamonly'],
            ['member', 'member:groups']
        );

        $this->assertSame(
            $expected_base + [
                'groups' => [
                    'non-member',
                    'admin'
                ]
            ],
            $user_data
        );

        //test due date scope
        $user_data = \GaletteOAuth2\Authorization\UserHelper::getUserData(
            $container,
            $adh1->id,
            [],
            ['member', 'member:due_date']
        );

        $this->assertSame(
            $expected_base + ['due_date' => null],
            $user_data
        );

        //test localization scope
        $user_data = \GaletteOAuth2\Authorization\UserHelper::getUserData(
            $container,
            $adh1->id,
            [],
            ['member', 'member:localization']
        );

        $address = new \stdClass();
        $address->locality = 'Martel';
        $address->region = '';
        $address->postal_code = '39 069';
        $address->country = 'Antarctique';
        $this->assertEquals(
            $expected_base + [
                'address' => $address
            ],
            $user_data
        );

        //test precise localization scope
        $user_data = \GaletteOAuth2\Authorization\UserHelper::getUserData(
            $container,
            $adh1->id,
            [],
            ['member', 'member:localization:precise']
        );

        $address->formatted = "66, boulevard De Oliveira\r\n\r\n39 069 Martel\r\nAntarctique";
        $address->street_address = "66, boulevard De Oliveira";
        $this->assertEquals(
            $expected_base + [
                'address' => $address
            ],
            $user_data
        );

        //test socials scope - no socials
        $user_data = \GaletteOAuth2\Authorization\UserHelper::getUserData(
            $container,
            $adh1->id,
            [],
            ['member', 'member:socials']
        );

        $this->assertSame(
            $expected_base,
            $user_data
        );

        //add socials
        $social = new \Galette\Entity\Social($this->zdb);
        $this->assertTrue(
            $social
                ->setType(\Galette\Entity\Social::MASTODON)
                ->setUrl('mastodon URL')
                ->setLinkedMember($adh1->id)
                ->store()
        );

        //get again, with socials
        $user_data = \GaletteOAuth2\Authorization\UserHelper::getUserData(
            $container,
            $adh1->id,
            [],
            ['member', 'member:socials']
        );

        $this->assertSame(
            $expected_base + [
                'socials' => [
                    \Galette\Entity\Social::MASTODON => 'mastodon URL'
                ]
            ],
            $user_data
        );


        //no scope => error
        $this->expectExceptionMessage('Default scope (member) has not been authorized.');
        \GaletteOAuth2\Authorization\UserHelper::getUserData(
            $container,
            $adh1->id,
            [],
            []
        );
    }

    /**
     * Test requireAdmin
     *
     * @return void
     */
    public function testRequireAdmin()
    {
        global $container;

        $this->initStatus();
        $adh1  = $this->getMemberOne();

        $this->expectExceptionMessage("Sorry, you can't login because your are not a team member.");
        \GaletteOAuth2\Authorization\UserHelper::getUserData(
            $container,
            $adh1->id,
            ['teamonly'],
            ['member']
        );
    }
}
