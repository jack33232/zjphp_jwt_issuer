<?php
namespace ZJPHP\JWT\Base;

use ZJPHP\Base\ZJPHP;
use ZJPHP\Facade\Database;
use ZJPHP\Base\Kit\ArrayHelper;
use ZJPHP\JWT\Base\JwtSystemModel;

class JwtSystemVault
{
    public static function getByAppId($app_id, $fields = [], $with_deleted = false, $lock = false)
    {
        $query = Database::table('jwt_systems')
            ->where('app_id', $app_id)
            ->select([
                'id',
                'app_id',
                'app_secret',
                'base_url',
                'ip_whitelist'
            ]);

        if (!empty($fields)) {
            $query->addSelect($fields);
        }

        if ($with_deleted === false) {
            $query->whereNull('deleted_at');
        }

        switch ($lock) {
            case 'S':
                $query->sharedLock();
                break;
            case 'X':
                $query->lockForUpdate();
                break;
        }

        $jwt_system_obj = $query->first();
        if (is_null($jwt_system_obj)) {
            return null;
        }

        return new JwtSystemModel($jwt_system_obj);
    }
}
