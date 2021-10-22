<?php
/**
 * The Main file for Hibp
 * @package Hibp
 * @author SleePy <sleepy @ simplemachines (dot) org>
 * @copyright 2021
 * @license 3-Clause BSD https://opensource.org/licenses/BSD-3-Clause
 * @version 1.0
 */

/**
 * Checks the password against the Have-I-Been-Pwned database.
 *
 * @param string $password The password to check
 * @param bool $hashed If the password is hashed already or not.
 * @return bool The result if found or not.  If null, the check failed.
 */
function hibp_password(string $password, bool $hashed = false): ?bool
{
	global $smcFunc;

	if (!$hashed)
		$password = sha1($password);
	
	$passhash_prefix = $smcFunc['substr']($password, 0, 5);
	$passhash_suffix = $smcFunc['substr']($password, 5);

	$call_url = 'https://api.pwnedpasswords.com/range/' . $passhash_prefix;

	/*
	* SMF's fetch_web_data doesn't support sending headers, so we are limited in our API options
	* and could build our own to do this, but this works fine.
	*/
	$results = fetch_web_data($call_url);

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
function hibp_validatePassword(string $password, string $username, array $restrict_in, string &$pass_error): void
{
	global $modSettings;

	// If another hook has set this, leave it alone.
	if (!empty($pass_error) || empty($modSettings['enableHibP']))
		return;

	// Send it to the backend.
	$res = hibp_password($password);

	// If the result is true, we want to present a error to the prefix of $txt['profile_error_password_*']
	if ($res === true)
	{
		loadLanguage('Hibp');
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
function hibp_load_custom_profile_fields(int $memID, string $area): void
{
	global $modSettings;

	if ($area !== 'register' || empty($modSettings['enableHibPjs']))
		return;

	// <input type="password" name="passwrd1" id="smf_autov_pwmain" size="50" tabindex="3" class=" invalid_input">
	hibp_build_javascript('#smf_autov_pwmain', '#smf_autov_pwmain_div');
}
	

/**
 * When the password field is setup on the profile pages, send in some javascript.
 *
 * @calledby call_integration_hook('integrate_setup_profile_context', array(&$fields));
 * @param array $fields User profile fields we are loading.
 * @return void
 */
function hibp_setup_profile_context(array $fields): void
{
	global $modSettings;

	// If we are not loading the password field, don't bother.
	if (!in_array('passwrd1', $fields) || empty($modSettings['enableHibPjs']))
		return;

	// <input type="password" name="passwrd1" id="passwrd1" size="20" value="">
	hibp_build_javascript('#passwrd1', '#passwrd1');
}

function hibp_build_javascript(string $selector, string $errorSelector): void
{
	global $txt;

	loadLanguage('Hibp');

	// Add the JS.  From: https://github.com/emn178/js-sha1
	loadJavaScriptFile('sha1.js');

	/*
	 *	When the password is ok we use: <span class="main_icons valid"></span>
	 *	When the password is bad we use: <span class="main_icons error"></span>
	*/
	addInlineJavaScript('
		$(document).ready(function () {
			$(' . JavaScriptEscape($selector) . ').on("change", function (e){
				var $hibp_attachSelector = ' . JavaScriptEscape($errorSelector) . '
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
							$hibpBox = $($hibp_attachSelector).parent().append(' . JavaScriptEscape('<div class="errorbox pagesection" style="width: 78%;">' . $txt['profile_error_password_hibp']. '</div>') . ');
						
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
	
	/*
	<div class="errorbox pagesection" style="width: 78%;">test</div>
	*/
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
function hibp_general_security_settings(array &$config_vars): void
{
	global $txt;

	loadLanguage('Hibp');

	// Find the last password setting.
	foreach ($config_vars as $id => $val)
		if (is_array($val) && $val[1] == 'enable_password_conversion' && is_string($config_vars[$id + 1]) && $config_vars[$id + 1] == '')
			break;

	$varsA = array_slice($config_vars, 0, $id + 1);
	$varsB = array_slice($config_vars, $id + 1);

	$new_vars = array(
		'',
		array('check', 'enableHibP'),
		array('check', 'enableHibPjs'),
	);

	$config_vars = array_merge($varsA, $new_vars, $varsB);

	// Saving?
	if (isset($_GET['save']))
	{
		// Can't have one without the other.
		if (!empty($_POST['enableHibPjs']) && empty($_POST['enableHibP']))
			$_POST['enableHibP'] = $_POST['enableHibPjs'];
	}
}