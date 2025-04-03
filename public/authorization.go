package public

import (
	"CloudWaf/core"
	"CloudWaf/core/logging"
	"CloudWaf/public/db"
	"errors"
	"strconv"
)

type DataList struct {
	DataList []map[string]string `json:"data_list"`
}
type DataInfo struct {
	SiteName string `json:"site_name"`
}

func GetAuthInfo() int {
	au, _ := core.Auth()
	tmpMap := make(map[int]string)
	tmpMap[0] = "免费版"
	tmpMap[1] = "专业版"
	tmpMap[2] = "旗舰版"
	tmpMap[3] = "企业版"
	return au.Auth.Extra.Type
}

func GetSiteAuthInfo(siteName string, moduleType string) bool {
	au, _ := core.Auth()
	switch au.Auth.Extra.Type {
	case 0:
		return false
	case 3:
		return true
	}
	if au.Auth.Extra.Type != 3 {
		if siteName == "allsite" {
			return false
		}
	}
	if moduleType == "returnsource" && au.Auth.Extra.Type != 3 {
		return false
	}
	authNumber := au.Auth.SiteMap[moduleType]
	_, err := MySqlWithClose(func(db *db.MySql) (interface{}, error) {
		query := db.NewQuery()
		query.Table("site_auth_info").
			Where("types = ?", []any{moduleType}).
			Field([]string{"site_name"})

		result, err := query.Select()
		if err != nil {
			logging.Info("query err:", err)
			return 0, err
		}
		if result == nil {
			return 0, nil
		}
		isDel := 0
		for _, v := range result {
			data := struct {
				SiteName string `json:"site_name"`
			}{}
			err = MapToStruct(v, &data)
			if err != nil {
				continue
			}
			if data.SiteName == "allsite" {
				isDel++
			}
			if data.SiteName == siteName {
				return 0, nil
			}
		}
		if len(result)-isDel < authNumber {
			return 0, nil
		}
		return 0, errors.New("无授权信息")
	})
	if err != nil {
		return false
	}
	return true
}

func UpdateSiteAuthInfo(siteName string, moduleType string, status string) (string, error) {
	if status == "enable" && !GetSiteAuthInfo(siteName, moduleType) {
		return "", errors.New("无授权信息")
	}
	_, err := MySqlWithClose(func(db *db.MySql) (interface{}, error) {
		query := db.NewQuery()
		queryCheck := db.NewQuery()
		query.Table("site_auth_info").
			Where("types = ?", []any{moduleType}).
			Where("site_name = ?", []any{siteName}).
			Field([]string{"id", "number"}).Order("id", "desc")

		result, err := query.Find()
		if err != nil {
			return "", nil
		}
		if result == nil {
			switch status {
			case "enable":
				err := AddSiteAuthInfo(db, siteName, moduleType)
				if err != nil {
					logging.Error("插入授权信息失败：", err)

				}
			case "disable":
			}
		} else {
			err = UpdateSiteAuth(db, siteName, moduleType, status)
			if err != nil {
				logging.Error("更新授权信息失败：", err)
			}
		}
		queryCheck.Table("site_auth_info").
			Where("types = ?", []any{moduleType}).
			Where("site_name = ?", []any{siteName}).
			Field([]string{"id", "number"}).Order("id", "desc")
		checkResult, err := queryCheck.Find()
		if err != nil || checkResult == nil {
			return nil, err
		}
		data := struct {
			Id     int
			Number int
		}{}
		err = MapToStruct(checkResult, &data)
		if err != nil {
			return nil, err
		}
		if data.Number <= 0 {
			err = DelSiteAuthInfo(db, siteName, moduleType)
			if err != nil {
				return nil, err
			}
			return "sucess", nil
		}
		return "sucess", nil

	})
	if err != nil {
		return "", errors.New("更新授权信息失败")
	}
	return "授权信息更新成功", nil
}

func AddSiteAuthInfo(db *db.MySql, siteName string, moduleType string) error {
	number := 1
	sql := "INSERT INTO `site_auth_info` (`types`, `site_name`, `number`) VALUES ('" + moduleType + "', '" + siteName + "', " + strconv.Itoa(number) + ")"
	_, err := db.Exec(sql, false)
	if err != nil {
		return err
	}
	return nil
}

func UpdateSiteAuth(db *db.MySql, siteName string, moduleType string, statusStr string) error {
	sql := "UPDATE `site_auth_info` SET `number` = `number` + 1 WHERE `types` = '" + moduleType + "' AND `site_name` = '" + siteName + "'"
	if statusStr == "disable" {
		sql = "UPDATE `site_auth_info` SET `number` = `number` - 1 WHERE `types` = '" + moduleType + "' AND `site_name` = '" + siteName + "'"
	}
	_, err := db.Exec(sql, false)
	if err != nil {
		return err
	}
	return nil
}

func DelSpecificSiteAllAuthInfo(db *db.MySql, siteName string) error {
	query := db.NewQuery()
	_, err := query.Table("site_auth_info").Where("site_name = ?", []any{siteName}).Delete()
	if err != nil {
		return err
	}
	return nil
}

func DelSiteAuthInfo(db *db.MySql, siteName string, moduleType string) error {
	sql := "delete from `site_auth_info` where `types` = '" + moduleType + "' and `site_name` = '" + siteName + "'"
	_, err := db.Exec(sql, false)
	if err != nil {
		return err
	}
	return nil
}

func CheckSmartCcAuthStatus() {
	siteIdMap := GetAllSmartCcOpen()
	moduleType := "smart_cc"
	_, err := MySqlWithClose(func(db *db.MySql) (interface{}, error) {
		query := db.NewQuery()
		query.Table("site_auth_info").
			Where("types = ?", []any{moduleType}).
			Field([]string{"site_name"}).Order("id", "desc")

		result, err := query.Select()
		if err != nil {
			return "", nil
		}
		if len(result) == 0 {
			return "", nil

		}
		for _, v := range result {
			if _, ok := v["site_name"].(string); !ok {
				continue
			}
			if _, ok := siteIdMap[v["site_name"].(string)]; !ok {
				if v["site_name"].(string) == "allsite" {
					continue
				}
				err = DelSiteAuthInfo(db, v["site_name"].(string), moduleType)
				if err != nil {
					continue
				}
			}

		}
		return nil, nil
	})
	if err != nil {
		return
	}
}

func CheckSpecifyRegionAuthStatus() {
	siteIdMap := GetStartRulesByAllRegion()
	moduleType := "location"
	_, err := MySqlWithClose(func(db *db.MySql) (interface{}, error) {
		query := db.NewQuery()
		query.Table("site_auth_info").
			Where("types = ?", []any{moduleType}).
			Field([]string{"site_name"}).Order("id", "desc")

		result, err := query.Select()
		if err != nil {
			return "", nil
		}
		if len(result) == 0 {
			return "", nil

		}
		for _, v := range result {
			if _, ok := v["site_name"].(string); !ok {
				continue
			}
			if _, ok := siteIdMap[v["site_name"].(string)]; !ok {
				if v["site_name"].(string) == "allsite" {
					continue
				}
				err = DelSiteAuthInfo(db, v["site_name"].(string), moduleType)
				if err != nil {
					continue
				}
			}

		}
		return nil, nil
	})
	if err != nil {
		return
	}

}

func GetIsSpecifyVersion(versionNum int) bool {
	au, _ := core.Auth()
	if au.Auth.Extra.Type == versionNum {
		return true
	}
	return false
}
