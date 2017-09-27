<?php
namespace ZJPHP\JWT\Base;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Base\Model;
use ZJPHP\Facade\Database;
use ZJPHP\Facade\CastingMold;
use ZJPHP\Base\Kit\ArrayHelper;
use ZJPHP\Base\Event;
use ZJPHP\Base\Exception\InvalidParamException;

class JwtSystemModel extends Model
{
    public static $ormTable = 'jwt_systems';
    public static $ormPK = 'id';

    public function getJWTAudience($audience_id, $fields = [], $lock = false)
    {
        $query = Database::table('jwt_audience_map')
            ->where('system_id', $this->activeRecord->id)
            ->where('audience', $audience_id)
            ->select([
                'audience AS audience_id',
                'encrypt',
                'sign',
                'quota',
                'extra_payload'
            ]);

        if (!empty($fields)) {
            $query->addSelect($fields);
        }

        switch ($lock) {
            case 'S':
                $query->sharedLock();
                break;
            case 'X':
                $query->lockForUpdate();
                break;
        }

        $result = $query->first();

        if (!is_null($result)) {
            if (!empty($result->extra_payload)) {
                $result->extra_payload = json_decode($result->extra_payload, 'true');
            } else {
                $result->extra_payload = [];
            }
        }
        return $result;
    }
}
