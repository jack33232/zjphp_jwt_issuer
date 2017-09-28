<?php
namespace ZJPHP\JWT\Filter;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Component;
use ZJPHP\Base\FilterInterface;
use Klein\Exceptions\HttpException;

class IPWhitelist extends Component implements FilterInterface
{
    public function filter($request, $response, $service, $app, $router)
    {
        if (isset($app->ip_whitelist)) {
            $ip = $request->ip();
            if (!in_array($ip, $app->ip_whitelist)) {
                throw HttpException::createFromCode(403);
            }
        }
    }
}
