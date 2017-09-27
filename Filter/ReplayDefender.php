<?php
namespace ZJPHP\JWT\Filter;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Component;
use ZJPHP\Base\FilterInterface;
use ZJPHP\Base\Kit\ArrayHelper;
use ZJPHP\Base\Exception\InvalidConfigException;
use Klein\Exceptions\HttpException;
use ZJPHP\Facade\ZJRedis;

class ReplayDefender extends Component implements FilterInterface
{
    protected $timerSpan = 60; // Unit is 'second'
    protected $useNonce = false;

    public function filter($request, $response, $service, $app, $router)
    {
        // Get replay defender required params
        $request_params = $request->paramsPost()->all();
        $validate_timer_result = (!empty($request_params['timer'])
            && is_numeric($request_params['timer'])
            && ($request_params['timer'] + $this->timerSpan) >= time()
        );

        if ($validate_timer_result === false) {
            throw HttpException::createFromCode(403);
        }

        if ($this->useNonce) {
            $validate_nonce_result = (!empty($request_params['nonce'])
                && is_string($request_params['nonce'])
                && strlen($request_params['nonce']) === $this->useNonce->nonceStringSize
                && $this->validateNonce($app->app_id, $request_params['nonce'])
            );

            if ($validate_nonce_result === false) {
                throw HttpException::createFromCode(403);
            }
        }
    }

    protected function validateNonce($app_id, $nonce)
    {
        $redis_client = ZJRedis::connect();
        $key = ZJPHP::$app->getAppName() . ':NoncePool:app_id-' . $app_id . ':' . date('Ymd');
        $existed = $redis_client->exists($key);
        $cardinality = $redis_client->sCard($key);
        if ($cardinality > $this->useNonce->noncePoolSize) {
            $pop_extra = $redis_client->sPop($key, $cardinality - $this->useNonce->noncePoolSize);

            if (in_array($nonce, $pop_extra)) {
                return false;
            }
        }
        $result = $redis_client->sAdd($key, $nonce);
        if (!$existed) {
            $redis_client->expire($key, $this->useNonce->noncePoolTtl);
        }

        return $result;
    }



    public function setTimerSpan($value)
    {
        if (is_numeric($value) && $value <= 60 && $value >= 3) {
            $this->timerSpan = $value;
        }
    }

    public function setUseNonce($setting)
    {
        $default = [
            'noncePoolSize' => 100000,
            'noncePoolTtl' => 600, // seconds
            'nonceStringSize' => 32
        ];
        $setting = ArrayHelper::merge($default, $setting);
        $this->useNonce = (object) $setting;
    }
}
