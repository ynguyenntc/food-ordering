<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Foundation\Bus\DispatchesJobs;



 /**
 * @OA\Info(
 *     version="1.0",
 *     title="Example for response examples value"
 * )
 */
/**
 * @OA\Info(
 *      version="1.0.",
 *      title="Laravel Api Documentation",
 *      description="L5 Swagger",
 *      @OA\License(
 *          name="Apache 2.0",
 *          url="http://www.apache.org/licenses/LICENSE-2.0.html"
 *      )
 * )
 *
 * @OA\Server(
 *      url=L5_SWAGGER_CONST_HOST,
 *      description="Demo API Server"
 * )
 */
class Controller extends BaseController
{
    use AuthorizesRequests, ValidatesRequests, DispatchesJobs;
}
