package providers

import (
	"CloudWaf/core"
	"CloudWaf/public"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"math/big"
	random "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func init() {
	sp := &selfSignedCertProvider{
		certFile:       core.AbsPath("./ssl/certificate.pem"),
		privateKeyFile: core.AbsPath("./ssl/privateKey.pem"),
		pfxFile:        core.AbsPath("./ssl/baota_root.pfx"),
		pfxPwdFile:     core.AbsPath("./ssl/root_password.pl"),
	}
	registerProviderAlways(sp.Run)
}

type selfSignedCertProvider struct {
	certFile       string
	privateKeyFile string
	pfxFile        string
	pfxPwdFile     string
}

func (sp *selfSignedCertProvider) Run() {
	_, certFileExists := os.Stat(sp.certFile)
	_, privateKeyFileExists := os.Stat(sp.privateKeyFile)

	if certFileExists == nil && privateKeyFileExists == nil {
		return
	}
	if err := sp.createOnline(); err != nil {
		if err := sp.createOffline(); err != nil {
			return
		}
	}
}

func (sp *selfSignedCertProvider) createOnline() error {

	serverIp, localIp := core.GetServerIp()

	data := map[string]any{
		"action":     "get_domain_cert",
		"company":    "宝塔面板",
		"panel":      1,
		"uid":        0,
		"access_key": strings.Repeat("B", 32),
		"domain":     serverIp + "," + localIp,
	}
	client := public.GetHttpClient(60)
	bs, err := json.Marshal(data)
	if err != nil {
		return err
	}
	dataValues, err := url.ParseQuery("data=" + string(bs))
	if err != nil {
		return err
	}
	resp, err := client.PostForm("https://api.bt.cn/bt_cert", dataValues)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	resultBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return errors.New("在线申请自签证书失败")
	}
	m := struct {
		Status   bool   `json:"status"`
		Cert     string `json:"cert"`
		Key      string `json:"key"`
		Pfx      string `json:"pfx"`
		Password string `json:"password"`
		Msg      string `json:"msg"`
	}{}
	if err = json.Unmarshal(resultBytes, &m); err != nil {
		return err
	}
	if !m.Status {
		return errors.New("在线申请自签证书失败：" + m.Msg)
	}

	if err := os.WriteFile(sp.certFile, []byte(m.Cert), fs.ModePerm); err != nil {
		return err
	}

	if err := os.WriteFile(sp.privateKeyFile, []byte(m.Key), fs.ModePerm); err != nil {
		return err
	}

	pfxBs, err := base64.StdEncoding.DecodeString(m.Pfx)

	if err != nil {
		return err
	}

	if err := os.WriteFile(sp.pfxFile, pfxBs, fs.ModePerm); err != nil {
		return err
	}

	if err := os.WriteFile(sp.pfxPwdFile, []byte(m.Password), fs.ModePerm); err != nil {
		return err
	}

	return nil
}

func (sp *selfSignedCertProvider) createOffline() error {
	err := os.MkdirAll(core.AbsPath("./ssl"), 0644)
	if err != nil {
		return err
	}
	csr, key, err := sp.createCertWithDynamic()
	if err != nil {
		return err
	}
	err = os.WriteFile(sp.certFile, csr, fs.ModePerm)
	if err != nil {
		return err
	}

	err = os.WriteFile(sp.privateKeyFile, key, fs.ModePerm)

	if err != nil {
		return err
	}

	return nil
}

func (sp *selfSignedCertProvider) createCertWithRoot(rootCa, rootKey []byte) ([]byte, []byte, error) {

	ca, caKey, err := sp.loadRootCertificate(rootCa, rootKey)

	if err != nil {
		return []byte{}, []byte{}, err
	}
	templateCsr := sp.generateCertTemplate()
	csr, key, err := sp.generateCert(ca, templateCsr, caKey)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	return csr, key, nil
}

func (sp *selfSignedCertProvider) createCertWithDynamic() ([]byte, []byte, error) {
	templateCa := sp.generateCACertTemplate()

	caCsr, caKey, err := sp.generateCACert(templateCa)

	if err != nil {
		return []byte{}, []byte{}, err
	}

	return sp.createCertWithRoot(caCsr, caKey)
}

func (sp *selfSignedCertProvider) loadRootCertificate(rootCa, rootKey []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	caBlock, _ := pem.Decode(rootCa)
	rootCert, err := x509.ParseCertificate(caBlock.Bytes)

	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(rootKey)
	praKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return rootCert, praKey, nil
}

func (sp *selfSignedCertProvider) generateCACertTemplate() *x509.Certificate {
	commonName := "CloudWaf"
	rd := random.New(random.NewSource(time.Now().UnixNano()))
	cer := &x509.Certificate{
		SerialNumber: big.NewInt(rd.Int63()),
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"BT"},
			OrganizationalUnit: []string{"BT"},
			Province:           []string{"DongGuan"},
			CommonName:         commonName,
			Locality:           []string{"DongGuan"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		EmailAddresses:        []string{"cloudwaf@bt.com"},
	}

	return cer
}

func (sp *selfSignedCertProvider) generateCertTemplate() *x509.Certificate {
	serverIp, localIp := core.GetServerIp()
	commonName := "CloudWaf"
	rd := random.New(random.NewSource(time.Now().UnixNano()))
	cer := &x509.Certificate{
		SerialNumber: big.NewInt(rd.Int63()),
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"BT"},
			OrganizationalUnit: []string{"BT"},
			Province:           []string{"DongGuan"},
			CommonName:         commonName,
			Locality:           []string{"DongGuan"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		EmailAddresses:        []string{"cloudwaf@bt.com"},
		IPAddresses:           []net.IP{net.ParseIP(serverIp), net.ParseIP(localIp)},
		DNSNames:              []string{},
	}

	return cer
}

func (sp *selfSignedCertProvider) generateCACert(templateCert *x509.Certificate) ([]byte, []byte, error) {
	priKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	ca, err := x509.CreateCertificate(rand.Reader, templateCert, templateCert, &priKey.PublicKey, priKey)
	if err != nil {
		return nil, nil, err
	}
	caPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca,
	}
	ca = pem.EncodeToMemory(caPem)
	buf := x509.MarshalPKCS1PrivateKey(priKey)
	keyPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: buf,
	}
	key := pem.EncodeToMemory(keyPem)

	return ca, key, nil
}

func (sp *selfSignedCertProvider) generateCert(rootCert, templateCert *x509.Certificate, rootKey *rsa.PrivateKey) ([]byte, []byte, error) {
	priKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.CreateCertificate(rand.Reader, templateCert, rootCert, &priKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	caPem := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca,
	}
	ca = pem.EncodeToMemory(caPem)
	buf := x509.MarshalPKCS1PrivateKey(priKey)
	keyPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: buf,
	}
	key := pem.EncodeToMemory(keyPem)

	return ca, key, nil
}
