<?php
namespace SimpleSAML\Module\cloudfront\Auth\Process;

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

    private $profile;
    private $version;
    private $region;

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
     * @var boolean|null (default = true) Indicates that the cookies should
     * use a Canned Policy. A Canned Policy requires "CloudFront-Expires",
     * "CloudFront-Signature" and "CloudFront-Key-Pair-Id" cookies. If
     * useCustomPolicy is set to true then it will always be used instead of
     * useCannedPolicy.
     * @see https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-cookies.html#private-content-choosing-canned-custom-cookies
     */
    private $useCannedPolicy;

    /**
     * @var boolean|null (default = false) Indicates that the cookies
     * should use a Custom Policy. A Custom Policy requires "CloudFront-Policy",
     * "CloudFront-Signature" and "CloudFront-Key-Pair-Id" cookies.
     * @see https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-signed-cookies.html#private-content-choosing-canned-custom-cookies
     *
     * @todo Implement custom policy support
     */
    private $useCustomPolicy;

    /**
     * @var integer|null (default = 86400) The number of seconds added to
     * time() and set as the unix timestamp for the "CloudFront-Expires" cookie
     * and the expiration time for "CloudFront-Policy" and
     * "CloudFront-Signature" cookies. If this value is not provided then the
     * cookies are created with the same lifetime as the user's SAML assertion.
     * If the SAML assertion does not have an expiration then
     * DEFAULT_LIFETIME_SECONDS is used.
     * @see https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-setting-signed-cookie-canned-policy.html#private-content-canned-policy-signature-cookies
     * @see https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-setting-signed-cookie-custom-policy.html#private-content-custom-policy-statement-cookies-procedure
     */
    private $cloudFrontExpires;

    /**
     * @var string|null (default = '/') Indicates a URL path that must exist in the requested
     * URL in order to send cookie header. This is useful if your CloudFront
     * implementation needs to provide access to multiple URLs, as cookies of
     * the same name can exist with different paths. So, we can create separate
     * instances of the cookies, using the Cookie Path as an identifier for
     * each URL.
     * @see https://stackoverflow.com/a/43769658/6654624
     * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Scope_of_cookies
     */
    private $cookiePath;

    /**
     * @var string|null (default = "Host" header) Indicates the allowed hosts
     * which can receive the cookies.
     * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Scope_of_cookies
     */
    private $cookieDomain;

    /**
     * @var boolean|null (default = true) Indicates if the cookies should only
     * be transferred over HTTPS.
     * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#Secure_and_HttpOnly_cookies
     */
    private $cookieSecure;

    /**
     * @var boolean|null (default = false) Indicates if the cookies should be
     * available to JavaScript's Document.cookie API. A cookie set to HttpOnly
     * will NOT be available to this API, to prevent cross-site scripting
     * attacks.
     */
    private $cookieHttpOnly;

    const DEFAULT_VERSION = '2018-11-05';
    const DEFAULT_REGION = 'us-east-1';
    const DEFAULT_USE_CANNED_POLICY = true;
    const DEFAULT_USE_CUSTOM_POLICY = false;
    const DEFAULT_LIFETIME_SECONDS = 86400;
    const DEFAULT_COOKIE_PATH = '/';
    const DEFAULT_COOKIE_SECURE = true;
    const DEFAULT_COOKIE_HTTP_ONLY = false;
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

        $this->profile = $config['profile'] ?? '';
        $this->version = $config['version'] ?? self::DEFAULT_VERSION;
        $this->region = $config['region'] ?? self::DEFAULT_REGION;

        $this->useCustomPolicy = boolval($config['useCustomPolicy'] ?? self::DEFAULT_USE_CUSTOM_POLICY);
        $this->useCannedPolicy = $this->useCustomPolicy ? false : boolval($config['useCannedPolicy'] ?? self::DEFAULT_USE_CANNED_POLICY);

        $cloudFrontExpiresDateTime = new \DateTime();
        $cloudFrontExpiresDateTime->add(
            new \DateInterval(sprintf(
                'PT%dS'
                , $config['cloudFrontExpires'] ?? $this->getSessionLifetime() ?? self::DEFAULT_LIFETIME_SECONDS
            ))
        );
        $this->cloudFrontExpires = $cloudFrontExpiresDateTime->getTimestamp();

        $this->cookiePath = $config['cookiePath'] ?? self::DEFAULT_COOKIE_PATH;
        $this->cookieDomain = $config['cookieDomain'] ?? apache_request_headers()['Host'] ?? '';
        $this->cookieSecure = $config['cookieSecure'] ?? self::DEFAULT_COOKIE_SECURE;
        $this->cookieHttpOnly = $config['cookieHttpOnly'] ?? self::DEFAULT_COOKIE_HTTP_ONLY;
    }

    /**
     * Process the CloudFront authentication response
     *
     * @param array $request The request
     * @return void
     */
    public function process(&$request)
    {
        try
        {
            $cloudFrontClient = new \Aws\CloudFront\CloudFrontClient([
                'version' => $this->version
                , 'region' => $this->region
            ]);

            if ($this->useCannedPolicy)
            {
                $this->setCookies($this->getCannedPolicyCookies($cloudFrontClient));
            }

            if ($this->useCustomPolicy)
            {
                $this->setCookies($this->getCustomPolicyCookies($cloudFrontClient));
            }
        }
        catch (\InvalidArgumentException $ex)
        {
            Logger::debug(sprintf('%s: getCookies: %s', self::MODULE_ALIAS, $ex->getMessage()));
            return false;
        }

        return true;
    }

    private function getCannedPolicyCookies($cloudFrontClient)
    {
        $cookies = $cloudFrontClient->getSignedCookie([
            'url' => $this->url
            , 'expires' => $this->cloudFrontExpires
            , 'private_key' => $this->privateKeyFile
            , 'key_pair_id' => $this->keyPairId
        ]);

        Logger::debug(sprintf('%s: canned_policy_cookies: %s', self::MODULE_ALIAS, print_r($cookies, 1)));

        return $cookies;
    }

    private function getCustomPolicyCookies($cloudFrontClient)
    {
        $customPolicy = json_encode(
            ['Statement' => [['Resource' => $this->url, 'Condition' => ['DateLessThan' => ['AWS:EpochTime' => $this->cloudFrontExpires]]]]]
            , JSON_UNESCAPED_SLASHES
        );

        $cookies = $cloudFrontClient->getSignedCookie([
            'policy' => $customPolicy
            , 'private_key' => $this->privateKeyFile
            , 'key_pair_id' => $this->keyPairId
        ]);

        Logger::debug(sprintf('%s: custom_policy: %s', self::MODULE_ALIAS, print_r($customPolicy, 1)));
        Logger::debug(sprintf('%s: custom_policy_cookies: %s', self::MODULE_ALIAS, print_r($cookies, 1)));

        return $cookies;
    }

    private function setCookies($cookies)
    {
        $params =
        [
            'path' => $this->cookiePath
            , 'domain' => $this->cookieDomain
            , 'secure' => $this->cookieSecure
            , 'httponly' => $this->cookieHttpOnly
            , 'expire' => $this->cloudFrontExpires
        ];

        foreach ($cookies as $name => $value)
        {
            Logger::debug(sprintf("%s: Setting cookie '%s = %s'", self::MODULE_ALIAS, $name, $value));
            \SimpleSAML\Utils\HTTP::setCookie(strval($name), strval($value), $params, true);
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

