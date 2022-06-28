package routers

import (
	"alipay_lifeapp/controllers"
	beego "github.com/beego/beego/v2/server/web"
)

func init() {
	beego.Router("/", &controllers.MainController{})
	beego.Router("/ali/gateway", &controllers.AliopenController{}, "get,post:GateWay")      // ali open 网关
	beego.Router("/ali/callback", &controllers.AliopenController{}, "get,post:AliCallBack") // ali open 授权回调地址

}
