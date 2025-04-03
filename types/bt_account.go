package types

type BtAccountInfo struct {
	AccessKey string `json:"access_key"`
	Ip        string `json:"ip"`
	SecretKey string `json:"secret_key"`
	ServerId  string `json:"server_id"`
	Uid       int    `json:"uid"`
	Username  string `json:"username"`
}

type VersionInfo struct {
	Version     string `json:"version"`
	Description string `json:"description"`
	CreateTime  int64  `json:"create_time"`
}
