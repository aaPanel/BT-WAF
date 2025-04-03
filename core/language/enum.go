package language

const (
	CN = "CN"
	EN = "EN"
)

var (
	VALID_LANGUAGE = []string{CN, EN}
	TRANS_MAP      = map[string]map[string]string{
		CN: {
			"user.login.param.username.empty":         "请输入用户名",
			"user.login.param.password.empty":         "请输入密码",
			"user.login.opt_log.fail":                 "登录IP：%s，登录地点：%s",
			"user.login.opt_log.success":              "用户登录成功，登录IP：%s，登录地点：%s",
			"user.login.fail.too_many":                "连续登录失败次数过多，请%d秒后重试",
			"user.login.param.validate_code.empty":    "请填写验证码",
			"user.login.param.validate_code_id.empty": "缺少参数：图形验证码ID",
			"user.login.validate_code.expire":         "验证码已过期",
			"user.login.validate_code.incorrect":      "验证码错误",
			"user.login.password.expire":              "密码已过期，请联系管理员重置密码，您还可以尝试[%d]次",
			"user.login.incorrect":                    "用户名或密码错误，您还可以尝试[%d]次",
			"user.two_auth.validate.fail":             "动态口令错误!",
			"user.logout.opt_log.success":             "用户退出登录",
		},
		EN: {
			"user.login.param.username.empty":         "Please enter your username",
			"user.login.param.password.empty":         "Please enter your password",
			"user.login.opt_log.fail":                 "Login IP：%s，Location：%s",
			"user.login.opt_log.success":              "Login Successfully. Login IP：%s，Location：%s",
			"user.login.fail.too_many":                "Too many login failed, please wait %d seconds after retry",
			"user.login.param.validate_code.empty":    "Please enter validate code",
			"user.login.param.validate_code_id.empty": "Missing parameter: validate_code_id",
			"user.login.validate_code.expire":         "Your validate code has been expired",
			"user.login.validate_code.incorrect":      "Incorrect validate code",
			"user.login.password.expire":              "Your password has been expired, Please contact your administrator. You can try %d more times",
			"user.login.incorrect":                    "Username or password incorrect, you can try %d more times",
			"user.two_auth.validate.fail":             "Authenticate failed!",
			"user.logout.opt_log.success":             "Logout Successfully",
		},
	}
)
