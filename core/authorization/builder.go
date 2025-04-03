package authorization

import (
	"CloudWaf/core/common"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	serverIdPath = common.AbsPath("./data/.sid")
	serverId     ServerId
	mutex        = sync.Mutex{}
)

func init() {
	serverId = GenerateServerId()
}

type ServerId []byte

func (s ServerId) String() string {
	return fmt.Sprintf("%s-%s-%s-%s-%s", string(s[:8]), string(s[8:12]), string(s[12:16]), string(s[16:20]), string(s[20:]))
}

func SID() string {
	return string(serverId)
}

func UUID() string {
	return serverId.String()
}

func GenerateServerId() (result ServerId) {
	if err := os.MkdirAll(filepath.Dir(serverIdPath), 0644); err != nil {
		panic(err)
	}
	if _, err := os.Stat(serverIdPath); err == nil {
		bs, err := os.ReadFile(serverIdPath)

		if err == nil {
			return bs
		}
	}
	mutex.Lock()
	defer mutex.Unlock()
	if _, err := os.Stat(serverIdPath); err == nil {
		bs, err := os.ReadFile(serverIdPath)

		if err == nil {
			return bs
		}
	}

	mac, err := getFirstMAC()
	if err != nil {
		mac = time.Now().String()
	}

	h := md5.New()
	h.Write([]byte(mac))
	hb := h.Sum(nil)

	result = make([]byte, hex.EncodedLen(len(hb)))
	hex.Encode(result, hb)

	if err = os.WriteFile(serverIdPath, result, 0644); err != nil {
		panic(err)
	}

	return result
}

func getFirstMAC() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		if len(iface.HardwareAddr) != 0 {
			return iface.HardwareAddr.String(), nil
		}
	}

	return "", errors.New("Failed to get MAC address")
}
