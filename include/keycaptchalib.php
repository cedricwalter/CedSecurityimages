<?php
/**
 * @version        SecurityImages
 * @package
 * @copyright    Copyright (C) 2004-2012 Cedric Walter. All rights reserved.
 * @copyright    www.cedricwalter.com / www.waltercedric.com
 *
 * @license        GNU/GPL, see LICENSE.php
 *
 * SecurityImages is free software. This version may have been modified pursuant
 * to the GNU General Public License, and as distributed it includes or
 * is derivative of works licensed under the GNU General Public License or
 * other free or open source software licenses.
 * See COPYRIGHT.php for copyright notices and details.
 */

defined('_JEXEC') or die;

class SecurityImagesKeyCaptcha 
{

		private $c_kc_keyword = "accept";
		private $p_kc_visitor_ip = "";
		private $p_kc_session_id = "";
		private $p_kc_web_server_sign = "";
		private $p_kc_web_server_sign2 = "";
		private $p_kc_js_code = "";
		private $p_kc_private_key = "JAUqMcNdQxjvKKBvvqWGXBz";
		private $userid = null;
		
		
		function __construct($a_private_key='', $userid='')
		{
			if ( $a_private_key != '' ) {
				$this->p_kc_private_key = $a_private_key;
			}
			
			$this->userid = $userid;

			$this->p_kc_session_id = uniqid() . '-3.4.0.001';
			$this->p_kc_visitor_ip = $_SERVER["REMOTE_ADDR"];
		}
		
		
		private function getJS()
		{
		  return "<!-- KeyCAPTCHA code (www.keycaptcha.com)--><script language='JavaScript'>var s_s_c_user_id = '".$this->userid."';var s_s_c_session_id = '#KC_SESSION_ID#';var s_s_c_captcha_field_id = 'capcode';var s_s_c_submit_button_id = 'postbut';var s_s_c_web_server_sign = '#KC_WSIGN#';var s_s_c_web_server_sign2 = '#KC_WSIGN2#';</script><script language=JavaScript src='http://backs.keycaptcha.com/swfs/cap.js'></script><!-- end of KeyCAPTCHA code-->";
		}


		public function get_web_server_sign($use_visitor_ip = 0)
		{
			return md5($this->p_kc_session_id . (($use_visitor_ip) ? ($this->p_kc_visitor_ip) :("")) . $this->p_kc_private_key);
		}



		function http_get($path)
		{
			$arr = parse_url($path);
			$host = $arr['host'];
			$page = $arr['path'];
			if ( $page=='' ) {
				$page='/';
			}
			if ( isset( $arr['query'] ) ) {
				$page.='?'.$arr['query'];
			}
			$errno = 0;
			$errstr = '';
			$fp = fsockopen ($host, 80, $errno, $errstr, 30);
			if (!$fp){ return ""; }
			$request = "GET $page HTTP/1.0\r\n";
			$request .= "Host: $host\r\n";
			$request .= "Connection: close\r\n";
			$request .= "Cache-Control: no-store, no-cache\r\n";
			$request .= "Pragma: no-cache\r\n";
			$request .= "User-Agent: KeyCAPTCHA\r\n";
			$request .= "\r\n";

			fwrite ($fp,$request);
			$out = '';

			while (!feof($fp)) $out .= fgets($fp, 250);
			fclose($fp);
			$ov = explode("close\r\n\r\n", $out);

			return $ov[1];
		}

		public function check_result($response)
		{
			$kc_vars = explode("|", $response);
			if ( count( $kc_vars ) < 4 )
			{
				return false;
			}
			if ($kc_vars[0] == md5($this->c_kc_keyword . $kc_vars[1] . $this->p_kc_private_key . $kc_vars[2]))
			{
				if (stripos($kc_vars[2], "http://") !== 0)
				{
					$kc_current_time = time();
					$kc_var_time = split('[/ :]', $kc_vars[2]);
					$kc_submit_time = gmmktime($kc_var_time[3], $kc_var_time[4], $kc_var_time[5], $kc_var_time[1], $kc_var_time[2], $kc_var_time[0]);
					if (($kc_current_time - $kc_submit_time) < 15)
					{
						return true;
					}
				}
				else
				{
					if ($this->http_get($kc_vars[2]) == "1")
					{
						return true;
					}
				}
			}
			return false;
		}

		public function render_js ()
		{
			$js = $this->getJS();
			
			if ( isset($_SERVER['HTTPS']) && ( $_SERVER['HTTPS'] == 'on' ) )
			{
				$js = str_replace ("http://","https://", $js);
			}
			$js = str_replace ("#KC_SESSION_ID#", $this->p_kc_session_id, $js);
			$js = str_replace ("#KC_WSIGN#", $this->get_web_server_sign(1), $js);
			$js = str_replace ("#KC_WSIGN2#", $this->get_web_server_sign(), $js);
			return $js;
		}
}