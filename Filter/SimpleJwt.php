<?php
namespace ZJPHP\JWT\Filter;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Component;
use ZJPHP\Base\FilterInterface;
use Klein\Exceptions\HttpException;
use ZJPHP\JWT\Facade\JwtIssuer;
use ZJPHP\Base\Kit\StringHelper;

class SimpleJwt extends Component implements FilterInterface
{
    protected $audience = BASE_URL;

    public function filter($request, $response, $service, $app, $router)
    {
        $jwt_str = trim(substr($request->headers()->get('Authorization'), strlen(JwtIssuer::getJwtSchema())));

        $app->jwt = $jwt = JwtIssuer::verifyJwt($jwt_str, $this->audience);
    }

    public function setAudience($audience)
    {
        $this->audience = $audience;
    }
}
