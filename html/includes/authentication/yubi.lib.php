<?php

/* Copyright (C) 2014 Daniel Preussker <f0o@devilcode.org>
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Edited by Matthew "Mattz0r" Scully <matt@mattz0r.me.uk> taken from twofactor.lib.php
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * YubiKey Library
 * @author Mattz0r <matt@mattz0r.me.uk>
 * @copyright 2015 Mattz0r, LibreNMS
 * @license GPL
 * @package LibreNMS
 * @subpackage Authentication
 */

/**
* Written Logic for the process
* 
* We must referene the config.php file, as this is where the clientID and secretKEY will be stored.
* We need to obtain the OTP this is the last 32 characters of the input, we must take the first part of the input and link to the user's twofactor ID.
* example: vvtrehgfucctltkbvhrfrrnjvtljbbnvkduhnnvrjcib Needs to be split like this: vvtrehgfucct (Client ID), ltkbvhrfrrnjvtljbbnvkduhnnvrjcib (OTP)
* We need to reject the login if the clientID doesn't match what's stored in the database.
* Once we have all the information we need, submit the data to the YubiCloud for verification, if it matches, success, if not, denied!
*/


/**
* Include files
*/

require_once $config['install_dir'].'/html/includes/authentication/Yubico.php';

/*
* Variables
*/

$yubi = new Auth_Yubico('$config['yubico']['clientID']', '$config['yubico']['secretKEY']');
$opt = substr($_POST['twofactor'];, -32);
$auth = $yubi->verify($otp);

/*
* This is the input form for YubiKey
* Original code by f0o, styled by Mattz0r
*/


function twofactor_form($form=true) {
        global $config;
        $ret = "";
        if ($form) {
                $ret .= '
      <div class="row">
        <div class="col-md-offset-4 col-md-4">
          <div class="panel panel-default">
            <div class="panel-heading">
              <h3 class="panel-title">
                <center>
                  <img src="images/librenms_logo_light.png">
                </center>
              </h3>
            </div>
            <div class="panel-body">
              <div class="container-fluid">
                  <form class="form-horizontal" role="form" action="" method="post" name="twofactorform">';
        }
        $ret .= '
        <div class="form-group">
          <div class="col-md-12">
            <input type="text" name="twofactor" id="twofactor" class="form-control" autocomplete="off" placeholder="Press your YubiKey button!" />
          </div>
        </div>
        <div class="form-group">
          <div class="col-md-12">
            <button type="submit" class="btn btn-default btn-block" name="submit" type="submit">Login</button>
          </div>
         </div>
        </div>';
        $ret .= '<script>document.twofactorform.twofactor.focus();</script>';
        if ( $form ) {
                $ret .= '
      </form>';
        }
        return $ret;
}



/**
 * Authentication logic - Wrote by f0o - Edited by Mattz0r
 * @return void
 */
function yubikey_auth() {
        global $auth_message, $twofactorform, $config;
        $twofactor = dbFetchRow('SELECT twofactor FROM users WHERE username = ?', array($_SESSION['username']));
        if ( empty($twofactor['twofactor']) ) {
                $_SESSION['twofactor'] = true;
    }
    else {
                $twofactor = json_decode($twofactor['twofactor'],true);
                if ( $twofactor['fails'] >= 3 && (!$config['twofactor_lock'] || (time()-$twofactor['last']) < $config['twofactor_lock']) ) {
                        $auth_message = "Too many failures, please ".($config['twofactor_lock'] ? "wait ".$config['twofactor_lock']." seconds" : "contact administrator").".";
        }
        else {
                        if ( !$_POST['twofactor'] ) {
                                $twofactorform = true;
            }
            else {
                                if ( ($server_c = PEAR::isError($auth) ) {
                                        $twofactor['fails']++;
                                        $twofactor['last'] = time();
                                        $auth_message = "Wrong Two-Factor Token.";
                }
                else {
                                        if ( $twofactor['counter'] !== false ) {
                                                if ( $server_c !== true && $server_c !== $twofactor['counter'] ) {
                                                        $twofactor['counter'] = $server_c+1;
                        }
                        else {
                                                        $twofactor['counter']++;
                                                }
                                        }
                                        $twofactor['fails'] = 0;
                                        $_SESSION['twofactor'] = true;
                                }
                                dbUpdate(array('twofactor' => json_encode($twofactor)),'users','username = ?',array($_SESSION['username']));
                        }
                }
        }
}

