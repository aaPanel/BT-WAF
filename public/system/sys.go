package system

import (
	"CloudWaf/core"
	"CloudWaf/core/common"
	"CloudWaf/types"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

type netIO struct {
	Sent uint64
	Recv uint64
}

type diskIO struct {
	ReadBytes           uint64
	WriteBytes          uint64
	IoTime              uint64
	ReadBytesPerSecond  uint64
	WriteBytesPerSecond uint64
	IoPercent           float64
}

type Sys struct {
	mutexCpu       sync.Mutex
	lastCpuTime    cpu.TimesStat
	lastGetCpuTime int64
	lastCpuPercent float64

	mutexNet         sync.Mutex
	lastGetNetIOTime int64
	lastNetIOBytes   map[string]netIO
	lastNetIOList    []types.NetIO

	mutexDisk             sync.Mutex
	lastGetDiskIoTime     int64
	lastDiskIo            map[string]*diskIO
	updateLastDiskIoMutex sync.RWMutex
}

func (sys *Sys) GetSystemInfo() types.SystemInfo {
	sysInf := types.SystemInfo{}

	sysInf.Host = sys.getHostInfo()

	rg := core.NewRecoveryGoGroup(-1)

	rg.Add(func() {
		sysInf.CPU = sys.getCPUInfo()
	})

	sysInf.Mem = sys.getSystemMemInfo()

	rg.Add(func() {
		sysInf.DiskList = sys.getDiskList()
	})

	rg.Add(func() {

		sysInf.NetIOList = sys.getNetIOList()
	})

	sysInf.Loadavg = sys.getLoadAvg()

	rg.Run(nil)

	return sysInf
}

func (sys *Sys) getHostInfo() types.Host {

	info, err := host.Info()

	if err != nil {
		return types.Host{}
	}

	return types.Host{
		HostName:        info.Hostname,
		BootTime:        info.BootTime,
		UpTime:          info.Uptime,
		Procs:           info.Procs,
		OS:              info.OS,
		Platform:        info.Platform,
		PlatformFamily:  info.PlatformFamily,
		PlatformVersion: info.PlatformVersion,
		KernelVersion:   info.KernelVersion,
		KernelArch:      info.KernelArch,
	}
}

func (sys *Sys) getCPUInfo() types.CPU {
	sys.mutexCpu.Lock()
	defer sys.mutexCpu.Unlock()

	cpuinfo, err := cpu.Info()

	if err != nil {
		return types.CPU{}
	}

	logicals, err := cpu.Counts(true)

	if err != nil {
		return types.CPU{}
	}

	cpuTime, err := cpu.Times(false)

	if err != nil {
		return types.CPU{}
	}

	curTime := time.Now().UnixMilli()

	if sys.lastGetCpuTime == 0 {
		sys.lastCpuTime = cpuTime[0]
		sys.lastGetCpuTime = curTime

		time.Sleep(1 * time.Second)
		curTime += 1000
		cpuTime, err = cpu.Times(false)

		if err != nil {
			return types.CPU{}
		}
	}

	totalPercent := sys.lastCpuPercent

	t1Tot := sys.lastCpuTime.User + sys.lastCpuTime.System + sys.lastCpuTime.Irq + sys.lastCpuTime.Softirq + sys.lastCpuTime.Steal + sys.lastCpuTime.Guest + sys.lastCpuTime.GuestNice + sys.lastCpuTime.Idle + sys.lastCpuTime.Iowait + sys.lastCpuTime.Nice
	t2Tot := cpuTime[0].User + cpuTime[0].System + cpuTime[0].Irq + cpuTime[0].Softirq + cpuTime[0].Steal + cpuTime[0].Guest + cpuTime[0].GuestNice + cpuTime[0].Idle + cpuTime[0].Iowait + cpuTime[0].Nice

	if runtime.GOOS == "linux" {
		t1Tot -= sys.lastCpuTime.Guest
		t1Tot -= sys.lastCpuTime.GuestNice

		t2Tot -= cpuTime[0].Guest
		t2Tot -= cpuTime[0].GuestNice
	}

	t1Busy := t1Tot - sys.lastCpuTime.Idle - sys.lastCpuTime.Iowait
	t2Busy := t2Tot - cpuTime[0].Idle - cpuTime[0].Iowait

	if curTime-sys.lastGetCpuTime > 300 && t2Busy > t1Busy {
		if t2Tot > t1Tot {
			totalPercent = math.Min(100, math.Max(0, (t2Busy-t1Busy)/(t2Tot-t1Tot)*100))
		} else {
			totalPercent = 100
		}
	}

	sys.lastCpuTime = cpuTime[0]
	sys.lastGetCpuTime = curTime

	sys.lastCpuPercent = common.Round(totalPercent, 2)

	if err != nil {
		return types.CPU{}
	}

	return types.CPU{
		ModelName:    cpuinfo[0].ModelName,
		LogicalCores: uint(logicals),
		Percent:      sys.lastCpuPercent,
	}
}

func (sys *Sys) getSystemMemInfo() types.Mem {
	m := types.Mem{}

	vm, err := mem.VirtualMemory()

	if err != nil {
		return m
	}

	m.Total = vm.Total
	m.Free = vm.Free
	m.Used = vm.Used
	m.UsedPercent = common.Round(vm.UsedPercent, 2)
	m.Buffers = vm.Buffers
	m.Cached = vm.Cached

	swap, err := mem.SwapMemory()

	if err == nil {
		m.SwapTotal = swap.Total
		m.SwapFree = swap.Free
		m.SwapUsed = swap.Used
		m.SwapUsedPercent = common.Round(swap.UsedPercent, 2)
	}

	return m
}

func (sys *Sys) getDiskList() []types.Disk {
	sys.mutexDisk.Lock()
	defer sys.mutexDisk.Unlock()

	if sys.lastDiskIo == nil {
		sys.lastDiskIo = make(map[string]*diskIO)
	}

	s := make([]types.Disk, 0, 16)

	partitions, err := disk.Partitions(false)

	if err != nil {
		return s
	}

	curTime := time.Now().UnixMilli()
	if sys.lastGetDiskIoTime == 0 {
		sys.lastGetDiskIoTime = curTime - 1000
	}

	timeDiffMilli := curTime - sys.lastGetDiskIoTime

	deltaSeconds := float64(timeDiffMilli) / 1000

	if deltaSeconds < 1 {
		deltaSeconds = 1
	}

	rg := core.NewRecoveryGoGroup(-1)

	i := 0
	for _, partition := range partitions {
		if len(partition.Device) > 9 && strings.Compare(partition.Device[:9], "/dev/loop") == 0 {
			continue
		}

		if strings.Compare(partition.Mountpoint, "/boot") == 0 {
			continue
		}

		s = append(s, types.Disk{})
		rg.Immediate(func(partition disk.PartitionStat, idx int) {
			d := types.Disk{
				Name:       partition.Device,
				Mountpoint: partition.Mountpoint,
				Fstype:     partition.Fstype,
				Opts:       partition.Opts,
			}

			usage, err := disk.Usage(partition.Mountpoint)

			if err == nil {
				d.Total = usage.Total
				d.Free = usage.Free
				d.Used = usage.Used
				d.UsedPercent = common.Round(usage.UsedPercent, 2)
				d.InodesTotal = usage.InodesTotal
				d.InodesFree = usage.InodesFree
				d.InodesUsed = usage.InodesUsed
				d.InodesUsedPercent = common.Round(usage.InodesUsedPercent, 2)
			}

			var last_io_time, last_read_bytes, last_write_bytes uint64

			sys.updateLastDiskIoMutex.RLock()
			if _, ok := sys.lastDiskIo[partition.Device]; !ok {
				sys.updateLastDiskIoMutex.RUnlock()

				io_list_1, err := disk.IOCounters(partition.Device)

				if err == nil {
					for _, io_info := range io_list_1 {
						last_read_bytes = io_info.ReadBytes
						last_write_bytes = io_info.WriteBytes
						last_io_time = io_info.IoTime

						sys.updateLastDiskIoMutex.Lock()
						sys.lastDiskIo[partition.Device] = &diskIO{
							ReadBytes:  io_info.ReadBytes,
							WriteBytes: io_info.WriteBytes,
							IoTime:     io_info.IoTime,
						}
						sys.updateLastDiskIoMutex.Unlock()
					}
				}

				time.Sleep(time.Second)

				sys.updateLastDiskIoMutex.RLock()
			}
			sys.updateLastDiskIoMutex.RUnlock()

			sys.updateLastDiskIoMutex.RLock()
			last_read_bytes = sys.lastDiskIo[partition.Device].ReadBytes
			last_write_bytes = sys.lastDiskIo[partition.Device].WriteBytes
			last_io_time = sys.lastDiskIo[partition.Device].IoTime
			sys.updateLastDiskIoMutex.RUnlock()

			io_list_2, err := disk.IOCounters(partition.Device)

			if err == nil {
				for _, io_info := range io_list_2 {
					d.ReadCount = io_info.ReadCount
					d.WriteCount = io_info.WriteCount
					d.ReadBytes = io_info.ReadBytes
					d.WriteBytes = io_info.WriteBytes
					d.ReadTime = io_info.ReadTime
					d.WriteTime = io_info.WriteTime
					d.Iops = io_info.IopsInProgress
					d.IoTime = io_info.IoTime

					sys.updateLastDiskIoMutex.RLock()
					d.ReadBytesPerSecond = sys.lastDiskIo[partition.Device].ReadBytesPerSecond
					d.WriteBytesPerSecond = sys.lastDiskIo[partition.Device].WriteBytesPerSecond
					sys.updateLastDiskIoMutex.RUnlock()

					if timeDiffMilli > 299 {
						if io_info.IoTime > last_io_time {
							d.IoPercent = common.Round(float64(io_info.IoTime-last_io_time)/float64(timeDiffMilli)*100, 2)
						} else {
							d.IoPercent = 0
						}

						if io_info.ReadBytes > last_read_bytes {
							d.ReadBytesPerSecond = uint64(float64(io_info.ReadBytes-last_read_bytes) / deltaSeconds)
						} else {
							d.ReadBytesPerSecond = 0
						}

						if io_info.WriteBytes > last_write_bytes {
							d.WriteBytesPerSecond = uint64(float64(io_info.WriteBytes-last_write_bytes) / deltaSeconds)
						} else {
							d.WriteBytesPerSecond = 0
						}

						sys.updateLastDiskIoMutex.Lock()
						sys.lastDiskIo[partition.Device].ReadBytes = io_info.ReadBytes
						sys.lastDiskIo[partition.Device].WriteBytes = io_info.WriteBytes
						sys.lastDiskIo[partition.Device].IoTime = io_info.IoTime
						sys.lastDiskIo[partition.Device].ReadBytesPerSecond = d.ReadBytesPerSecond
						sys.lastDiskIo[partition.Device].WriteBytesPerSecond = d.WriteBytesPerSecond
						sys.updateLastDiskIoMutex.Unlock()
					}
				}
			}

			s[idx] = d
		}, partition, i)

		i++
	}

	rg.Wait()

	return s
}

func (sys *Sys) getNetIOList() []types.NetIO {
	sys.mutexNet.Lock()
	defer sys.mutexNet.Unlock()

	ret := make([]types.NetIO, 0, 16)
	m := make(map[string]netIO)

	curTime := time.Now().UnixMilli()

	if sys.lastGetNetIOTime == 0 {
		sys.lastGetNetIOTime = curTime - 1000
	}

	timeDiffMilli := curTime - sys.lastGetNetIOTime

	if timeDiffMilli < 300 {
		return sys.lastNetIOList
	}

	deltaSeconds := float64(timeDiffMilli) / 1000

	if deltaSeconds < 1 {
		deltaSeconds = 1
	}

	if sys.lastNetIOBytes == nil {

		nios_1, err := net.IOCounters(true)
		if err != nil {
			return []types.NetIO{}
		}

		for _, nio := range nios_1 {
			if strings.Compare(nio.Name, "lo") == 0 {
				continue
			}

			m[nio.Name] = netIO{
				Sent: nio.BytesSent,
				Recv: nio.BytesRecv,
			}
		}
		sys.lastNetIOBytes = m

		time.Sleep(time.Second)

	} else {

		m = sys.lastNetIOBytes
	}

	nios_2, err := net.IOCounters(true)

	if err != nil {
		return []types.NetIO{}
	}

	for _, nio := range nios_2 {
		if strings.Compare(nio.Name, "lo") == 0 {
			continue
		}

		lastNio := m[nio.Name]
		ret = append(ret, types.NetIO{
			Name:          nio.Name,
			Sent:          nio.BytesSent,
			Recv:          nio.BytesRecv,
			SentPerSecond: uint64(float64(nio.BytesSent-lastNio.Sent) / deltaSeconds),
			RecvPerSecond: uint64(float64(nio.BytesRecv-lastNio.Recv) / deltaSeconds),
		})

		m[nio.Name] = netIO{
			Sent: nio.BytesSent,
			Recv: nio.BytesRecv,
		}
	}

	sys.lastGetNetIOTime = curTime
	sys.lastNetIOBytes = m
	sys.lastNetIOList = ret

	return ret
}

func (sys *Sys) getLoadAvg() types.Loadavg {
	LoadavgDict := types.Loadavg{}
	file, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return LoadavgDict
	}

	splitFile := strings.Split(string(file), " ")
	Last1minFloat, _ := strconv.ParseFloat(splitFile[0], 64)
	Last5minFloat, _ := strconv.ParseFloat(splitFile[1], 64)
	Last15minFloat, _ := strconv.ParseFloat(splitFile[2], 64)
	LoadavgDict.Last1min = Last1minFloat
	LoadavgDict.Last5min = Last5minFloat
	LoadavgDict.Last15min = Last15minFloat

	return LoadavgDict
}
