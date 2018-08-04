<?php

namespace SimpleSAML\Module\cloudfront\Auth\Process;

class CloudFront extends \SimpleSAML\Auth\ProcessingFilter
{
    private $keyPairId;
    private $privateKeyFile;
    private $url;
    private $useCannedPolicy;
    private $useCustomPolicy;
    private $cookieLifetime;
    private $cookiePath;
    private $cookieDomain;
    private $cookieSecure;
    private $cookieHttpOnly;

    /**
     * Create a new CloudFront instance
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);

        $this->keyPairId = $config['keyPairId'] ?? null;
        $this->privateKeyFile = $config['privateKeyFile'] ?? null;
        $this->url = $config['url'] ?? null;
        $this->useCannedPolicy = boolval($config['useCannedPolicy'] ?? true);
        $this->useCustomPolicy = boolval($config['useCustomPolicy'] ?? false);
        $this->cookieLifetime = $config['cookieLifetime'] ?? null;
        $this->cookiePath = $config['cookiePath'] ?? '/';
        $this->cookieDomain = $config['cookieDomain'] ?? '';
        $this->cookieSecure = $config['cookieSecure'] ?? true;
        $this->cookieHttpOnly = $config['cookieHttpOnly'] ?? true;
    }

    public function process(&$request)
    {
        if (!empty($this->keyPairId) && !empty($this->privateKeyFile))
        {
            $cookieSigner = new \Aws\CloudFront\CookieSigner($this->keyPairId, $this->privateKeyFile);

            try
            {
                // Use assertion expiration time if no lifetime is provided
                if (is_null($this->cookieLifetime))
                {
                    $this->cookieLifetime = $this->getSessionLifetime();
                }

                // If cookie lifetime = 0 then the cookie will expire with the browser.
                // So, the policy will be generated without an expiration time.
                $lifetime = intval($this->cookieLifetime) === 0 ? null : intval($this->cookieLifetime);
                $this->cookieLifetime = $lifetime;

                $expiration = new \DateTime();
                $expiration->add(new \DateInterval(sprintf('PT%dS', $lifetime)));
                $timestamp = $expiration->getTimestamp();

                $signedCookies = $cookieSigner->getSignedCookie($this->url, $timestamp, $this->getPolicy($timestamp));

                $this->setCookies($signedCookies);
            }
            catch (\InvalidArgumentException $ex)
            {
                return false;
            }
            finally
            {
                $cookieSigner = null;
            }
        }

        return true;
    }

    private function getPolicy($timestamp)
    {
        return $this->useCannedPolicy ? $this->getCannedPolicy($timestamp) : $this->getCustomPolicy($timestamp);
    }

    private function getCannedPolicy($timestamp)
    {
        $policy = ['Statement' => [['Resource' => $this->url]]];

        if (!is_null($timestamp))
        {
            $policy['Statement'][0]['Condition'] = ['DateLessThan' => ['AWS:EpochTime' => $timestamp]];
        }

        return json_encode($policy, JSON_UNESCAPED_SLASHES);
    }

    private function getCustomPolicy($timestamp)
    {

    }

    private function setCookies($cookies)
    {
        $params =
        [
            'path' => $this->cookiePath
            , 'domain' => $this->cookieDomain
            , 'secure' => $this->cookieSecure
            , 'httponly' => $this->cookieHttpOnly
            , 'lifetime' => $this->cookieLifetime
        ];

        foreach ($cookies as $name => $value)
        {
            \SimpleSAML\Utils\HTTP::setCookie($name, $value, $params, true);
        }
    }

    private function getSessionLifetime()
    {
        $sessionHandler = \SimpleSAML\SessionHandler::getSessionHandler();
        return intval($sessionHandler->getCookieParams()['lifetime'] ?? 0);
    }
}

?>
