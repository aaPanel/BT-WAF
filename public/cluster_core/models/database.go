package models

import (
	"CloudWaf/types"
	"encoding/json"
	"errors"
	"net"
	"strings"
)

type ClusterBandwidth struct {
	Upload   float64 `json:"upload"`
	Download float64 `json:"download"`
}

type ClusterNodeDetail struct {
	ServerIp         string           `json:"server_ip"`
	ServerIpLocation string           `json:"server_ip_location"`
	LocalIp          string           `json:"local_ip"`
	Host             types.Host       `json:"host"`
	CPU              types.CPU        `json:"cpu"`
	Mem              types.Mem        `json:"mem"`
	Bandwidth        ClusterBandwidth `json:"bandwidth"`
}

func (cnd ClusterNodeDetail) Validate() error {
	cnd.ServerIp = strings.TrimSpace(cnd.ServerIp)

	if cnd.ServerIp == "" {
		return errors.New("IP地址不能为空")
	}

	if net.ParseIP(cnd.ServerIp) == nil {
		return errors.New("IP地址格式错误")
	}

	return nil
}

func (cnd ClusterNodeDetail) ToJson() (string, error) {
	cnd.ServerIp = strings.TrimSpace(cnd.ServerIp)
	cnd.ServerIpLocation = strings.TrimSpace(cnd.ServerIpLocation)

	bs, err := json.Marshal(cnd)

	if err != nil {
		return "", err
	}

	return string(bs), nil
}

type ClusterNodeRealtime struct {
	Qps          uint64        `json:"qps"`
	Upload       uint64        `json:"upload"`
	Download     uint64        `json:"download"`
	ResourceTime uint64        `json:"resource_time"`
	Loadavg      types.Loadavg `json:"loadavg"`
	CPU          types.CPU     `json:"cpu"`
	Mem          types.Mem     `json:"mem"`
	DiskList     []types.Disk  `json:"disk_list"`
	NetIOList    []types.NetIO `json:"net_io_list"`
}

func (c ClusterNodeRealtime) NetIOSummary() types.NetIO {
	netIO := types.NetIO{}

	for _, v := range c.NetIOList {
		netIO.Sent += v.Sent
		netIO.Recv += v.Recv
		netIO.SentPerSecond += v.SentPerSecond
		netIO.RecvPerSecond += v.RecvPerSecond
	}

	return netIO
}

func (c ClusterNodeRealtime) DiskIOSummary() types.Disk {
	diskIO := types.Disk{}

	for _, v := range c.DiskList {
		diskIO.ReadBytes += v.ReadBytes
		diskIO.WriteBytes += v.WriteBytes
		diskIO.ReadBytesPerSecond += v.ReadBytesPerSecond
		diskIO.WriteBytesPerSecond += v.WriteBytesPerSecond
	}

	return diskIO
}
