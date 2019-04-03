<?php
namespace SimpleSAML\Module\ssphpecrs\Auth\Process;

/**
 * Amazon CloudFront Authentication Processing Filter
 * 
 * Generate CloudFront signed cookies, which allow you to control who can access
 * your content. Signed cookies are more practical than signed url's when your
 * end-user needs access to multiple restricted files, such as subscription-based
 * downloads, monthly news content or premium video content.
 * 
 * @author Aaron St. Clair <astclair2010@gmail.com>
 * @license https://github.com/BAGELreflex/ssphp-cloudfront/LICENSE.md
 * @version 1.0.0
 */

use \SimpleSAML\Logger;

class CloudFront extends \SimpleSAML\Auth\ProcessingFilter
{
    /**
     * @var string The Access Key ID for an active CloudFront key pair. An AWS
     * account with an active CloudFront key pair which is authorized to create
     * genuine signed cookies for your CloudFront distribution is known as a
     * "trusted signer".
     */
    private $keyPairId;
    
    /**
     * @var string The fully qualified path name to private key file created for
     * the CloudFront key pair passed in for $keyPairId. This file must be
     * located on the local file system.
     */
    private $privateKeyFile;
    
    /**
     * @var string The PEM-encoded private key created for the CloudFront key
     * pair passed in for $keyPairId. This private key must be base64 encoded.
     * Permanently storing the private key on the local file system in a
     * location that is readable by the web-server can introduce security
     * concerns. Many web-server's support the ability to populate data into
     * memory or to access environment variables. This is a more secure method
     * of passing secure data to your application than allowing it to read a
     * private file directly.
     * 
     * @example Apache provides the "SetEnv" directive, which will allow you to
     * base64 encode your private key file, then store the value in your
     * apache configuration, which is read by the service daemon instead of the
     * apache user.
     * 
     * @todo Implement this
     */
    private $privateKeyBase64;
    
    /**
     * @var string The base URL, including your query strings (if any), to the
     * CloudFront resource(s) for which the cookies should be authorized.
     * @see https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-creating-signed-url-custom-policy.html#private-content-custom-policy-statement-values
     * 
     * @todo Make this optional (If you omit the Resource parameter for a web
     * distribution, users can access all of the objects associated with any
     * distribution that is associated with the key pair that you use to create
     * the signed URL.
     * @see https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-creating-signed-url-custom-policy.html#private-content-custom-policy-statement-values
     */
    private $url;
    
    /**
     * @var boolean Indicates that the cookies should use a Canned Policy.
     * @see https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-cookies.html#private-content-choosing-canned-custom-cookies
     */
    private $useCannedPolicy;
    
    /**
     * @var boolean|null Indicates that the cookies should use a Custom Policy.
     * @see https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-cookies.html#private-content-choosing-canned-custom-cookies
     * 
     * @todo Implement custom policy support
     */
    private $useCustomPolicy;
    
    /**
     * @var integer|null The number of seconds for which the cookies should be
     * valid. If this value is not provided the the cookies are created with the
     * same lifetime as the user's SAML assertion cookies.
     */
    private $cookieLifetime;
    
    /**
     * @var string|null Indicates a URL path that must exist in the requested
     * URL in order to send cookie header. This is useful if your CloudFront
     * implementation needs to provide access to multiple URLs, as cookies of
     * the same name can exist with different paths. So, we can create separate
     * instances of the cookies, using the Cookie Path as an identifier for
     * each URL. If a path is not provided then the cookies are created using
     * the default path of '/'.
     * @see https://stackoverflow.com/a/43769658/6654624
     * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Scope_of_cookies
     */
    private $cookiePath;
    
    /**
     * @var string|null Indicates the allowed hosts which can receive the
     * cookies. If a domain is not provided the the cookie is created using the
     * domain of the host, excluding subdomains.
     * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Scope_of_cookies
     */
    private $cookieDomain;
    
    /**
     * @var boolean|null Indicates if the cookies should only be transferred
     * over HTTPS. If this value is not provided then the cookies are created
     * using the secure flag.
     * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies
     */
    private $cookieSecure;
    
    /**
     * @var boolean|null Indicates if the cookies should be available to
     * JavaScript's Document.cookie API. A cookie set to HttpOnly will NOT be
     * available to this API, to prevent cross-site scripting attacks. If this
     * value is not provided then the cookies are created using the HttpOnly
     * flag.
     */
    private $cookieHttpOnly;
    
    const MODULE_ALIAS = 'SSPHP-CloudFront';
    
    /**
     * Initialize CloudFront authentication processing filter
     * 
     * Validates and parses the configuration
     * 
     * @param array $config Configuration needed to setup the CloudFront
     * authentication processing filter.
     * @param mixed $reserved For future use
     * 
     * @throws \SimpleSAML\Error\Exception if the configuration is not valid.
     */
    public function __construct($config, $reserved)
    {
        assert(is_array($config));
        parent::__construct($config, $reserved);

        $this->keyPairId = $this->requireConfig($config, 'keyPairId', 'STRING');
        $this->privateKeyFile = $this->requireConfig($config, 'privateKeyFile', 'STRING');
        $this->url = $this->requireConfig($config, 'url', 'STRING');
        
        $this->useCannedPolicy = boolval($config['useCannedPolicy'] ?? true);
        $this->useCustomPolicy = boolval($config['useCustomPolicy'] ?? false);
        $this->cookieLifetime = $config['cookieLifetime'] ?? null;
        $this->cookiePath = $config['cookiePath'] ?? '/';
        $this->cookieDomain = $config['cookieDomain'] ?? '';
        $this->cookieSecure = $config['cookieSecure'] ?? true;
        $this->cookieHttpOnly = $config['cookieHttpOnly'] ?? true;
    }
    
    /**
     * Process the CloudFront authentication response
     * 
     * @param array $request The request
     * @return void
     */
    public function process(&$request)
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
            
            $policy = $this->getPolicy($timestamp);

            Logger::debug(sprintf('%s: cookieLifetime: %d', self::MODULE_ALIAS, $this->cookieLifetime));            
            Logger::debug(sprintf('%s: policy: %s', self::MODULE_ALIAS, print_r($policy, 1)));

            $signedCookies = $cookieSigner->getSignedCookie($this->url, $timestamp, $policy);

            $this->setCookies($signedCookies);
        }
        catch (\InvalidArgumentException $ex)
        {
            Logger::debug(sprintf('%s: cookieSigner->getSignedCookies: %s', self::MODULE_ALIAS, $ex->getMessage()));
            return false;
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
            Logger::debug(sprintf("%s: Setting cookie '%s = %s'", self::MODULE_ALIAS, $name, $value));
            \SimpleSAML\Utils\HTTP::setCookie($name, $value, $params, true);
        }
    }

    private function getSessionLifetime()
    {
        $sessionHandler = \SimpleSAML\SessionHandler::getSessionHandler();
        return intval($sessionHandler->getCookieParams()['lifetime'] ?? 0);
    }
    
    private function requireConfig($config, $key, $type)
    {
        if (!array_key_exists($key, $config))
        {
            throw new \SimpleSAML\Error\Exception(sprintf(
                '%s: %s must be provided (%s provided)'
                , self::MODULE_ALIAS
                , $key
                , var_export($config[$key], true)
            ));
        }
        
        switch ($type)
        {
            case 'INT':
                if (!is_int($config[$key]))
                {
                    throw new \SimpleSAML\Error\Exception(sprintf(
                        '%s: %s must be a valid integer (%s provided)'
                        , self::MODULE_ALIAS
                        , $key
                        , var_export($config[$key], true)
                    ));
                }
                break;
            case 'BOOL':
                if (!is_bool($config[$key]))
                {
                    throw new \SimpleSAML\Error\Exception(sprintf(
                        '%s: %s must be a valid boolean (%s provided)'
                        , self::MODULE_ALIAS
                        , $key
                        , var_export($config[$key], true)
                    ));
                }
                break;
            case 'STRING':
                if (!is_string($config[$key]) || empty($config[$key]))
                {
                    throw new \SimpleSAML\Error\Exception(sprintf(
                        '%s: %s must be a valid string (%s provided)'
                        , self::MODULE_ALIAS
                        , $key
                        , var_export($config[$key], true)
                    ));
                }
                break;
            default:
                if (empty($config[$key]))
                {
                    throw new \SimpleSAML\Error\Exception(sprintf(
                        '%s: %s must not be empty (%s provided)'
                        , self::MODULE_ALIAS
                        , $key
                        , var_export($config[$key], true)
                    ));
                }
        }
        
        return $config[$key];
    }
}

?>
