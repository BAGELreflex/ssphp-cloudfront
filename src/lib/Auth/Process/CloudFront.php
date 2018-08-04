<?php

namespace SimpleSAML\Module\cloudfront;

class CloudFront extends \SimpleSAML\Auth\ProcessingFilter
{
    /**
     * Create a new CloudFront instance
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        
        error_log(print_r(['astclair' => 'Test123'], 1));
    }
    
    public function process(&$request)
    {
        // Do processing
        
        return true;
    }
}

?>