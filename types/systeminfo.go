package types

type SystemInfo struct {
	Host      Host    `json:"host"`
	CPU       CPU     `json:"cpu"`
	Mem       Mem     `json:"mem"`
	DiskList  []Disk  `json:"disk_list"`
	NetIOList []NetIO `json:"net_io_list"`
	Loadavg   Loadavg `json:"loadavg"`
}

type Host struct {
	HostName        string `json:"host_name"`
	BootTime        uint64 `json:"boot_time"`
	UpTime          uint64 `json:"up_time"`
	Procs           uint64 `json:"procs"`
	OS              string `json:"os"`
	Platform        string `json:"platform"`
	PlatformFamily  string `json:"platform_family"`
	PlatformVersion string `json:"platform_version"`
	KernelVersion   string `json:"kernel_version"`
	KernelArch      string `json:"kernel_arch"`
}

type CPU struct {
	ModelName    string  `json:"model_name"`
	LogicalCores uint    `json:"logical_cores"`
	Percent      float64 `json:"percent"`
}

type Loadavg struct {
	Last1min  float64 `json:"last1min"`
	Last5min  float64 `json:"last5min"`
	Last15min float64 `json:"last15min"`
}

type Mem struct {
	Total           uint64  `json:"total"`
	Free            uint64  `json:"free"`
	Buffers         uint64  `json:"buffers"`
	Cached          uint64  `json:"cached"`
	Used            uint64  `json:"used"`
	UsedPercent     float64 `json:"used_percent"`
	SwapTotal       uint64  `json:"swap_total"`
	SwapFree        uint64  `json:"swap_free"`
	SwapUsed        uint64  `json:"swap_used"`
	SwapUsedPercent float64 `json:"swap_used_percent"`
}

type Disk struct {
	Name                string   `json:"name"`
	Mountpoint          string   `json:"mountpoint"`
	Fstype              string   `json:"fstype"`
	Opts                []string `json:"opts"`
	Total               uint64   `json:"total"`
	Free                uint64   `json:"free"`
	Used                uint64   `json:"used"`
	UsedPercent         float64  `json:"used_percent"`
	InodesTotal         uint64   `json:"inodes_total"`
	InodesFree          uint64   `json:"inode_free"`
	InodesUsed          uint64   `json:"inodes_used"`
	InodesUsedPercent   float64  `json:"inodes_used_percent"`
	ReadCount           uint64   `json:"read_count"`
	WriteCount          uint64   `json:"write_count"`
	ReadBytes           uint64   `json:"read_bytes"`
	WriteBytes          uint64   `json:"write_bytes"`
	ReadTime            uint64   `json:"read_time"`
	WriteTime           uint64   `json:"write_time"`
	Iops                uint64   `json:"iops"`
	IoTime              uint64   `json:"io_time"`
	IoPercent           float64  `json:"io_percent"`
	ReadBytesPerSecond  uint64   `json:"read_bytes_per_second"`
	WriteBytesPerSecond uint64   `json:"write_bytes_per_second"`
}

type NetIO struct {
	Name          string `json:"name"`
	Sent          uint64 `json:"sent"`
	Recv          uint64 `json:"recv"`
	SentPerSecond uint64 `json:"sent_per_second"`
	RecvPerSecond uint64 `json:"recv_per_second"`
}
