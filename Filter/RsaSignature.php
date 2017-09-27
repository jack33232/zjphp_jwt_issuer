<?php
namespace ZJPHP\JWT\Filter;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Component;
use ZJPHP\Base\FilterInterface;
use ZJPHP\Base\Kit\ArrayHelper;
use Klein\Exceptions\HttpException;
use ZJPHP\JWT\Facade\Authentication;

class RsaSignature extends Component implements FilterInterface
{
    protected $algo = 'RS256';

    public function filter($request, $response, $service, $app, $router)
    {
        // Process request data
        $post_data = $request->paramsPost()->all();
        $get_data = $request->paramsGet()->all();
        $data_to_sign = ArrayHelper::merge($get_data, $post_data);
        $signature = $data_to_sign['signature'] ?? false;

        if ($signature === false) {
            throw HttpException::createFromCode(400);
        }

        unset($data_to_sign['signature']);

        $url = rtrim(ROOT_URL . $request->pathname(), '/');

        if (!Authentication::rsaVerify($data_to_sign, $signature, $url, $this->algo)) {
            throw HttpException::createFromCode(401);
        }
    }

    public function setAlgo($algo)
    {
        $this->algo = $algo;
    }
}
