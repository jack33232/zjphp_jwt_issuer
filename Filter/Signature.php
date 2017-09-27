<?php
namespace ZJPHP\JWT\Filter;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Component;
use ZJPHP\Base\FilterInterface;
use Klein\Exceptions\HttpException;
use ZJPHP\JWT\Facade\Authentication;
use ZJPHP\JWT\Base\JwtSystemVault;

class Signature extends Component implements FilterInterface
{
    public function filter($request, $response, $service, $app, $router)
    {
        if (isset($app->sign)) {
            if ($app->sign === true) {
                $this->verifyQuietMode($request, $response, $service, $app, $router);
            }
        } else {
            $this->verifyWildMode($request, $response, $service, $app, $router);
        }
    }

    protected function verifyWildMode($request, $response, $service, $app, $router)
    {
        // Process request data
        $request_data = $request->paramsPost()->all();
        // Validate request data
        $validate_result = (!empty($request_data['signature'])
            && !empty($request_data['app_id'])
            && is_string($request_data['signature'])
            && is_string($request_data['app_id'])
        );

        if ($validate_result === false) {
            throw HttpException::createFromCode(400);
        }

        // Get Platform secret
        $jwt_system = JwtSystemVault::getByAppId($request_data['app_id'], [], false, 'S');

        if (is_null($jwt_system)) {
            throw HttpException::createFromCode(401);
        }
        // Verify the user signature
        $signature = Authentication::sign($request_data, $jwt_system->app_secret);

        if ($request_data['signature'] !== $signature) {
            throw HttpException::createFromCode(401);
        }

        $app->app_id = $jwt_system->app_id;
        $app->app_secret = $jwt_system->app_secret;
        $app->jwt_system = $jwt_system;

        // IP White list
        if (!empty($jwt_system->ip_whitelist)) {
            $app->ip_whitelist = array_map('trim', explode(',', $jwt_system->ip_whitelist));
        }
    }

    protected function verifyQuietMode($request, $response, $service, $app, $router)
    {
        // Process request data
        $request_data = $request->paramsPost()->all();

        // Validate request data
        $validate_result = (!empty($request_data['signature'])
            && is_string($request_data['signature'])
        );

        if ($validate_result === false) {
            throw HttpException::createFromCode(400);
        }

        // Verify the user signature
        $signature = Authentication::sign($request_data, $app->session_key);
        if ($request_data['signature'] !== $signature) {
            throw HttpException::createFromCode(401);
        }
    }
}
