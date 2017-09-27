<?php
namespace ZJPHP\JWT\Facade;

use ZJPHP\Base\Facade;

class Authentication extends Facade
{
    /**
     * @inheritDoc
     */
    public static function getFacadeComponentId()
    {
        return 'authentication';
    }
}
