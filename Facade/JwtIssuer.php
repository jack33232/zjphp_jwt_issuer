<?php
namespace ZJPHP\JWT\Facade;

use ZJPHP\Base\Facade;

class JwtIssuer extends Facade
{
    /**
     * @inheritDoc
     */
    public static function getFacadeComponentId()
    {
        return 'jwtIssuer';
    }
}
