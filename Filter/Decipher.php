<?php
/**
 * Decipher is for decrypting POST data & re-fill POST data
 **/
namespace ZJPHP\JWT\Filter;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Component;
use ZJPHP\Base\FilterInterface;
use ZJPHP\Facade\Security;
use Klein\Exceptions\HttpException;
use ZJPHP\Base\Exception\InvalidParamException;

class Decipher extends Component implements FilterInterface
{
    public $supportEncode = ['base64', 'bin2hex'];

    public function filter($request, $response, $service, $app, $router)
    {
        // Only POST method is expected having ciphertext
        if ($app->encrypt && $request->method('post')) {
            $ciphertext = $request->paramsPost()->get('ciphertext');
            $encode = $request->paramsPost()->get('encode', null);

            if (!in_array($encode, $this->supportEncode)) {
                throw new InvalidParamException('Encode Not Support', 400);
            } elseif (!empty($encode)) {
                $ciphertext = $this->decodeCiphertext($ciphertext, $encode);
            }
            
            if (!empty($ciphertext)) {
                $post_data = $this->decipherParams($ciphertext, $app->session_key);
                // Replace post data to the decrypted version
                $request->paramsPost()->replace($post_data);
            }
        }
    }

    protected function decodeCiphertext($ciphertext, $encode)
    {
        switch ($encode) {
            case 'base64':
                $ciphertext = base64_decode($ciphertext, true);
                break;
            case 'bin2hex':
                $ciphertext = hex2bin($ciphertext);
                break;
        }

        if (empty($ciphertext)) {
            throw new InvalidParamException('Fail On Decode', 400);
        }

        return $ciphertext;
    }

    protected function decipherParams($ciphertext, $password)
    {
        $plaintext = Security::decryptByPassword($ciphertext, $password);
        $post_data = [];
        ltrim($plaintext, '?');
        parse_str($plaintext, $post_data);
        return $post_data;
    }
}
