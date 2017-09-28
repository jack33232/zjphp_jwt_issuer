<?php
namespace ZJPHP\JWT\Base;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Controller;
use Klein\Exceptions\HttpException;
use ZJPHP\Facade\Router;
use ZJPHP\Facade\Validation;
use ZJPHP\JWT\Facade\JwtIssuer;
use ZJPHP\ApiProxy\Facade\ApiProxy;
use ZJPHP\Facade\Security;

class AuthController extends Controller
{
    public function jwt($request, $response, $service, $app, $router)
    {
        $app_id = $app->app_id;
        $app_secret = $app->app_secret;
        $jwt_system = $app->jwt_system;
        $audience_id = $request->paramsPost()->get('audience');

        $audience = $jwt_system->getJWTAudience($audience_id);

        if (is_null($audience)) {
            throw HttpException::createFromCode(401);
        }

        $payload = [
            'appid' => $app_id,
            'encrypt' => $audience->encrypt,
            'sign' => $audience->sign
        ] + (array) $audience->extra_payload;

        $jwt = JwtIssuer::generateJwt($app_id, $audience->quota, $audience_id, $jwt_system->base_url, $payload);

       // Notify the Audience & get the response
        $notify_request = ApiProxy::getRequest(
            $audience_id,
            'notify_jwt',
            [
                'POST' => [
                    'jti' => $jwt->getHeader('jti'),
                    'encrypt' => $jwt->getClaim('encrypt', 'N'),
                    'sign' => $jwt->getClaim('sign', 'N'),
                    'expire_at' => $jwt->getClaim('exp', strtotime('2047-06-30 23:59:59'))
                ]
            ]
        );

        $notify_result = $notify_request->send();
        $session_key = null;
        if (isset($notify_result['session_key'])) {
            $session_key = $this->processSignSecret($notify_result['session_key'], $app_secret);
        }

        $response_data = [
            'jwt' => (string) $jwt,
            'session_key' => $session_key
        ];

        $response->code(201);
        $response->apiJson($response_data);
    }

    protected function processSignSecret($session_key, $app_secret)
    {
        $session_key = Security::asymmetricDecrypt($session_key);

        return [
            'cipher' => Security::getCipher(),
            'encode' => 'base64',
            'ciphertext' => base64_encode(Security::encryptByPassword($session_key, $app_secret))
        ];
    }
}
