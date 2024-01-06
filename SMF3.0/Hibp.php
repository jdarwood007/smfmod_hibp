<?php
/**
 * The Main file for Hibp
 * @package Hibp
 * @author SleePy <sleepy @ simplemachines (dot) org>
 * @copyright 2024
 * @license 3-Clause BSD https://opensource.org/licenses/BSD-3-Clause
 * @version 1.0
 */

#namespace SMF\Mod\ErrorPopup;

use SMF\Config;
use SMF\Db\DatabaseApi as Db;
use SMF\Lang;
use SMF\Theme;
use SMF\User;
use SMF\Utils;
use SMF\WebFetch;

class hibp
{
	/**
	 * Checks the password against the Have-I-Been-Pwned database.
	 *
	 * @param string $password The password to check
	 * @param bool $hashed If the password is hashed already or not.
	 * @return bool The result if found or not.  If null, the check failed.
	 */
	public static function checkPassword(string $password, bool $hashed = false): ?bool
	{
		if (!$hashed)
			$password = sha1($password);
	
		$passhash_prefix = Utils::entitySubstr($password, 0, 5);
		$passhash_suffix = Utils::entitySubstr($password, 5);

		$call_url = 'https://api.pwnedpasswords.com/range/' . $passhash_prefix;

		/*
		* SMF's fetch_web_data doesn't support sending headers, so we are limited in our API options
		* and could build our own to do this, but this works fine.
		*/
		$results = WebFetchApi::fetch($call_url);

		// Invalid results, just pass them through.
		if (empty($results))
			return null;

		// Sure we could make an array of the data, but we just want to see if its found.
		$found = preg_match(
			'~\s+' . preg_quote($passhash_suffix) . ':\d+~i',
			$results
			);

		// We found a result, its found.
		if ($found === 1)
			return true;
		// No result, return false.
		elseif ($found === 0)
			return false;

		// $found returned something invalid, also fail.
		return null;
	}

	/**
	 * Checks the password against the HiBP database.
	 *
	 * @calledby call_integration_hook('integrate_validatePassword', array($password, $username, $restrict_in, &$reg_error));
	 * @param string $password The password to check
	 * @param string $username Currently ignored by this hook.
	 * @param array $restrict_in Currently ignored by this hook.
	 * @param string $pass_error A password error if any.  If this is set, we won't process our hook.
	 * @return void
	 */
	public static function validatePassword(string $password, string $username, array $restrict_in, string &$pass_error): void
	{
		// If another hook has set this, leave it alone.
		if (!empty($pass_error) || empty(Config::$modSettings['enableHibP']))
			return;

		// Send it to the backend.
		$res = self::checkPassword($password);

		// If the result is true, we want to present a error to the prefix of $txt['profile_error_password_*']
		if ($res === true)
		{
			Lang::load('Hibp');
			$pass_error = 'hibp';
		}
	}

	/**
	 * When the password field is setup on the registration, send in some javascript.
	 *
	 * @calledby call_integration_hook('integrate_load_custom_profile_fields', array($memID, $area));
	 * @param array $fields User profile fields we are loading.
	 * @return void
	 */
	public static function addToRegistrationPage(int $memID, string $area): void
	{
		if ($area !== 'register' || empty(Config::$modSettings['enableHibPjs']))
			return;

		// <input type="password" name="passwrd1" id="smf_autov_pwmain" size="50" tabindex="3" class=" invalid_input">
		self::buildJavascript('#smf_autov_pwmain', '#smf_autov_pwmain_div');
	}
	

	/**
	 * When the password field is setup on the profile pages, send in some javascript.
	 *
	 * @calledby call_integration_hook('integrate_setup_profile_context', array(&$fields));
	 * @param array $fields User profile fields we are loading.
	 * @return void
	 */
	public static function addToProfileContext(array $fields): void
	{
		global $modSettings;

		// If we are not loading the password field, don't bother.
		if (!in_array('passwrd1', $fields) || empty($modSettings['enableHibPjs']))
			return;

		// <input type="password" name="passwrd1" id="passwrd1" size="20" value="">
		self::buildJavascript('#passwrd1', '#passwrd1');
	}

	public static function buildJavascript(string $selector, string $errorSelector): void
	{
		Lang::load('Hibp');

		// Add the JS.  From: https://github.com/emn178/js-sha1
		Theme::loadJavaScriptFile('sha1.js');

		/*
		 *	When the password is ok we use: <span class="main_icons valid"></span>
		 *	When the password is bad we use: <span class="main_icons error"></span>
		*/
		Theme::addInlineJavaScript('
			$(document).ready(function () {
				$(' . Utils::JavaScriptEscape($selector) . ').on("change", function (e){
					var $hibp_attachSelector = ' . Utils::JavaScriptEscape($errorSelector) . '
					var $passhash = sha1($(this).val());
					var $passhash_prefix = $passhash.substring(0, 5);
					var $passhash_suffix = $passhash.substring(5);
					var $passhash_regx = new RegExp("\\\\s+" + $passhash_suffix + ":\\\\d+", "i");
				 
					$.ajax({
						url: "https://api.pwnedpasswords.com/range/" + $passhash_prefix,
						type: "GET",
						dataType: "html",
						success: function (data, textStatus, xhr) {
							var $res = $passhash_regx.test(data);
						
							// Build the box.
							if (typeof $hibpBox === "undefined")
								$hibpBox = $($hibp_attachSelector).parent().append(' . Utils::JavaScriptEscape('<div class="errorbox pagesection" style="width: 78%;">' . Lang::$txt['profile_error_password_hibp']. '</div>') . ');
						
							// It was found.
							if ($res === true)
								$($hibpBox).find("div.errorbox").show();
							else if ($res === false)
								$($hibpBox).find("div.errorbox").hide();
						}				
					});
				});
			});
		');
	}

	/**
	 * Adds Hibp options to the mangage registration.
	 * General registration settings and Coppa compliance settings.
	 * Accessed by ?action=admin;area=regcenter;sa=settings.
	 * Requires the admin_forum permission.
	 *
	 * @param bool $return_config Whether or not to return the config_vars array (used for admin search)
	 * @return void|array Returns nothing or returns the $config_vars array if $return_config is true
	 */
	public static function addToGeneralSecuritySettings(array &$config_vars): void
	{
		Lang::load('Hibp');

		// Find the last password setting.
		foreach ($config_vars as $id => $val)
			if (is_array($val) && $val[1] == 'enable_password_conversion' && is_string($config_vars[$id + 1]) && $config_vars[$id + 1] == '')
				break;

		$varsA = array_slice($config_vars, 0, $id + 1);
		$varsB = array_slice($config_vars, $id + 1);

		$new_vars = [
			'',
			['check', 'enableHibP'],
			['check', 'enableHibPjs'],
		];

		$config_vars = array_merge($varsA, $new_vars, $varsB);

		// Saving?
		if (isset($_GET['save']))
		{
			// Can't have one without the other.
			if (!empty($_POST['enableHibPjs']) && empty($_POST['enableHibP']))
				$_POST['enableHibP'] = $_POST['enableHibPjs'];
		}
	}
}