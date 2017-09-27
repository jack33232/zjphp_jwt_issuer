<?php
namespace ZJPHP\JWT\Service;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Component;
use ZJPHP\Facade\Security;
use ZJPHP\Facade\Database;
use ZJPHP\Facade\ZJRedis;
use ZJPHP\Base\Exception\InvalidConfigException;
use ZJPHP\Base\Exception\InvalidCallException;
use ZJPHP\Base\Exception\InvalidParamException;
use ZJPHP\Base\Exception\DatabaseErrorException;
use Klein\Exceptions\HttpException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Signer\Keychain;
use Lcobucci\JWT\Signer\Rsa\Sha256;

class Authentication extends Component
{
    private $_jwtTtl = 7200; //Seconds, 2 hours
    private $_jwtRsa = [];
    private $_jwtIssuer = BASE_URL;
    private $_jwtSchema = 'Bearer';
    private $_jwtPoolThreshold = 5000;

    public function sign($data, $secret)
    {
        if (isset($data['signature'])) {
            unset($data['signature']);
        }

        ksort($data, SORT_NATURAL);
        $data_string = http_build_query($data, '', '&', PHP_QUERY_RFC3986);

        return Security::hash($data_string, 'sha256', $secret, false);
    }

    public function rsaSign($data, $base_url = '')
    {
        ksort($data, SORT_NATURAL);
        $data_string = $base_url . '?' . http_build_query($data, '', '&', PHP_QUERY_RFC3986);
        return Security::genDigitalSignature($data_string);
    }

    public function rsaVerify($data, $expected, $base_url = '')
    {
        ksort($data, SORT_NATURAL);
        $data_string = $base_url . '?' . http_build_query($data, '', '&', PHP_QUERY_RFC3986);
        return Security::verifyDigitalSignature($data_string, $expected);
    }

    public function generateJwt($app_id, $quota, $audience, $subject, $payload)
    {
        if ($this->jwtHasQuota($app_id, $audience, $quota)) {
            $jwt = $this->jwtCreate($audience, $subject, $payload);

            $jti = $jwt->getHeader('jti');

            // Log the issue
            Database::table('jwts')->insert([
                'jti' => $jti,
                'app_id' => $app_id,
                'audience' => $audience,
                'token' => (string) $jwt,
                'created_at' => date('Y-m-d H:i:s', $jwt->getClaim('iat'))
            ]);

            return $jwt;
        } else {
            throw new InvalidCallException('No more quota for JWT', 4001);
        }
    }

    public function acceptJwt($jti, $expire_at)
    {
        $jwt_pool_key = $this->_getJwtPoolKey();
        $redis_client = ZJRedis::connect();

        $result = $redis_client->zAdd($jwt_pool_key, $expire_at, $jti);

        if ($redis_client->zSize($jwt_pool_key)
            > $this->_jwtPoolThreshold) {
            $redis_client->zRemRangeByScore($jwt_pool_key, 0, time() - 1);
        }

        if ($result === false) {
            throw new DatabaseErrorException('Fail to accept JWT, pls retry.', 5001);
        }
    }

    public function genSessionKey($jti, $expire_at)
    {
        $session_key_pool_key = $this->_getJwtSessionKeyPoolKey($expire_at);
        $redis_client = ZJRedis::connect();

        $existed = $redis_client->exists($session_key_pool_key);
        $session_key = Security::generateRandomString(16);
        $redis_client->hSet($session_key_pool_key, $jti, $session_key);
        if (!$existed) {
            $pool_expire_at = date('Y-m-d 23:59:59', $expire_at);
            $redis_client->expireAt($session_key_pool_key, strtotime($pool_expire_at));
        }

        return $session_key;
    }

    public function subSaveSessionKey($jti, $session_key, $expire_at)
    {
        $session_key_pool_key = $this->_getJwtSessionKeyPoolKey($expire_at);
        $redis_client = ZJRedis::connect();

        $existed = $redis_client->exists($session_key_pool_key);
        $redis_client->hSet($session_key_pool_key, $jti, $session_key);
        if (!$existed) {
            $pool_expire_at = date('Y-m-d 23:59:59', $expire_at);
            $redis_client->expireAt($session_key_pool_key, strtotime($pool_expire_at));
        }

        return $session_key;
    }

    public function getSessionKey($jti, $expire_at)
    {
        $session_key_pool_key = $this->_getJwtSessionKeyPoolKey($expire_at);
        $redis_client = ZJRedis::connect();

        if ($redis_client->exists($session_key_pool_key)
            && $redis_client->hExists($session_key_pool_key, $jti)
        ) {
            return $redis_client->hGet($session_key_pool_key, $jti);
        } else {
            return null;
        }
    }

    public function verifyJwt($jwt_str, $audience)
    {
        try {
            $jwt = (new Parser())->parse((string) $jwt_str);
        } catch (\Exception $e) {
            throw HttpException::createFromCode(401);
        }
        $this->verifyJwtSignature($jwt);
        $this->verifyJwtClaims($jwt, $audience);
        $this->verifyJwtRovoke($jwt);

        return $jwt;
    }

    public function subVerifyJwt($jwt_str)
    {
        try {
            $jwt = (new Parser())->parse((string) $jwt_str);
        } catch (\Exception $e) {
            throw HttpException::createFromCode(401);
        }
        $this->verifyJwtSignature($jwt);

        return $jwt;
    }

    protected function verifyJwtRovoke($jwt)
    {
        $jti = $jwt->getHeader('jti');
        $jwt_pool_key = $this->_getJwtPoolKey();

        $redis_client = ZJRedis::connect();
        $existed = $redis_client->zScore($jwt_pool_key, $jti);
        if (is_null($existed)) {
            throw HttpException::createFromCode(401);
        }
    }

    protected function verifyJwtSignature($jwt)
    {
        $signer = new Sha256();

        $keychain = new Keychain();

        $result = $jwt->verify($signer, $keychain->getPublicKey($this->_jwtRsa['publicKey']));

        if ($result === false) {
            throw HttpException::createFromCode(401);
        }
    }

    protected function verifyJwtClaims($jwt, $audience)
    {
        $data = new ValidationData();
        $data->setIssuer($this->_jwtIssuer);
        $data->setAudience($audience);

        $result = $jwt->validate($data);
        if ($result === false) {
            throw HttpException::createFromCode(401);
        }
    }

    protected function jwtHasQuota($app_id, $audience, $quota)
    {
        $redis_client = ZJRedis::connect();
        $key = $this->_getJwtQuotaKey($app_id, $audience);
        if (!$redis_client->exists($key)) {
            $redis_client->set($key, 0);
            $redis_client->expireAt($key, strtotime('+1 day'));
            return true;
        }
        $daily_usage = $redis_client->incr($key);

        return $quota >= $daily_usage;
    }

    protected function jwtCreate($audience, $subject, $payload)
    {
        $signer = new Sha256();

        $keychain = new Keychain();

        $jti = $this->genJwtJti();

        $jwt_obj = (new Builder())->setIssuer($this->_jwtIssuer) // Configures the issuer (iss claim)
            ->setAudience($audience) // Configures the audience (aud claim)
            ->setSubject($subject) // Set the party who receive the token
            ->setId($jti, true) // Configures the id (jti claim), replicating as a header item
            ->setIssuedAt(time()) // Configures the time that the token was issue (iat claim)
            ->setExpiration(time() + $this->_jwtTtl); // Configures the expiration time of the token (nbf claim)

        foreach ($payload as $key => $val) {
            $jwt_obj->set($key, $val);
        }

        $jwt = $jwt_obj->sign($signer, $keychain->getPrivateKey($this->_jwtRsa['privateKey'], $this->_jwtRsa['privateKeyPwd'])) // creates a signature using your private key
            ->getToken(); // Retrieves the generated token

        return $jwt;
    }

    protected function genJwtJti()
    {
        return time() . Security::generateRandomString(24);
    }

    private function _getJwtPoolKey()
    {
        return ZJPHP::$app->getAppName() . ':JwtPool';
    }

    private function _getJwtSessionKeyPoolKey($expire_at)
    {
        return ZJPHP::$app->getAppName() . ':JwtSessionKeyPool-' . date('Ymd', $expire_at);
    }

    private function _getJwtQuotaKey($app_id, $audience)
    {
        return ZJPHP::$app->getAppName() . ':JwtPool-' . date('Ymd') . ':appid-' . $app_id . ':audience' . $audience;
    }

    public function setJwtTtl($ttl)
    {
        if (is_numeric($ttl)) {
            $this->_jwtTtl = intval($ttl);
        }
    }

    public function setJwtRsa($rsa_setting)
    {
        if (!isset($rsa_setting['publicKey']) || !isset($rsa_setting['privateKey']) || !isset($rsa_setting['privateKeyPwd'])) {
            throw new InvalidConfigException('RSA Setting incorrect.');
        }
        $this->_jwtRsa = $rsa_setting;
    }

    public function setJwtIssuer($issurer)
    {
        $this->_jwtIssuer = $issurer;
    }

    public function setJwtSchema($schema)
    {
        $this->_jwtSchema = $schema;
    }

    public function setJwtPoolThreshold($number)
    {
        if (is_numeric($number) && $number > 100 && $number < 10000) {
            $this->_jwtPoolThreshold = $number;
        }
    }

    public function getJwtSchema()
    {
        return $this->_jwtSchema;
    }
}
