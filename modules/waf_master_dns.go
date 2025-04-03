package modules

import (
	"CloudWaf/core"
	"CloudWaf/core/logging"
	"CloudWaf/public"
	"CloudWaf/public/db"
	"CloudWaf/public/encryption"
	"CloudWaf/types"
	"encoding/json"
	err "errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	alidns20150109 "github.com/alibabacloud-go/alidns-20150109/v4/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
)

const aesKey = "rOA3FLDroEC8quaA"

var (
	englishToChinese = map[string]string{"tencent": "腾讯云DNS", "aliyun": "阿里云DNS"}
	aliyunVersion    = map[string]string{"mianfei": "免费版", "version_personal": "个人版", "version_enterprise_basic": "企业标准版", "version_enterprise_advanced": "企业旗舰版", "version_cached_basic": "权威代理标准版"}
)

func init() {
	core.RegisterModule(&Wafmaster{})

}

func (m *Wafmaster) GetAllowLine(request *http.Request) core.Response {
	params := struct {
		Domain      string `json:"domain"`
		DomainGrade string `json:"domain_grade"`
		Types       string `json:"types"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	if params.Types == "tencent" {
		api, err := GetApiKey(params.Types)
		if err != nil {
			return core.Fail(err)
		}
		record := types.DnsRecord{}
		client, _ := initTencentClient(record, api)
		dnsRequest := dnspod.NewDescribeRecordLineListRequest()

		dnsRequest.Domain = common.StringPtr(record.Domain)
		dnsRequest.DomainId = common.Uint64Ptr(record.DomainId)
		dnsRequest.DomainGrade = common.StringPtr(params.DomainGrade)

		response, err := client.DescribeRecordLineList(dnsRequest)
		if _, ok := err.(*errors.TencentCloudSDKError); ok {
			return core.Fail(err)
		}
		if err != nil {
			panic(err)
		}
		return core.Success(response)
	}
	return core.Success("OK")
}

func GetApiKey(typeString string) (types.ApiKey, error) {
	api := types.ApiKey{}
	entryDnsData := types.EntryDnsData{}
	if !public.M("dns_info").Where("dns_name = ?", []any{typeString}).Exists() {
		return api, err.New("规则名称[" + englishToChinese[typeString] + "]不存在")
	}

	query := public.M("dns_info").
		Field([]string{"api_key"}).
		Where("dns_name = ?", []any{typeString})
	result, err := query.Find()
	if err != nil {
		return api, err
	}

	err = public.MapToStruct(result, &entryDnsData)
	if err != nil {
		return api, err
	}

	if err := json.Unmarshal([]byte(entryDnsData.Key), &api); err != nil {
		return api, err
	}
	api, err = decryptApiKey(api)
	if err != nil {
		return api, err
	}
	return api, nil
}

func CreateTencentRecord(record types.DnsRecord) error {
	api, err := GetApiKey("tencent")
	if err != nil {
		return err
	}
	client, _ := initTencentClient(record, api)
	dnsRequest := dnspod.NewCreateRecordRequest()

	dnsRequest.Domain = common.StringPtr(record.Domain)
	dnsRequest.SubDomain = common.StringPtr(record.SubDomain)
	dnsRequest.RecordType = common.StringPtr(record.RecordType)
	dnsRequest.RecordLine = common.StringPtr(record.RecordLine)
	dnsRequest.Value = common.StringPtr(record.Value)

	response, err := client.CreateRecord(dnsRequest)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		return err
	}
	if err != nil {
		panic(err)
	}
	logging.Debug("CreateTencentRecord response  %s", response.ToJsonString())
	return nil
}

func (m *Wafmaster) CreateRecord(request *http.Request) core.Response {

	record := types.DnsRecord{}
	if err := core.GetParamsFromRequestToStruct(request, &record); err != nil {
		return core.Fail(err)
	}
	api, err := GetApiKey("tencent")
	if err != nil {
		return core.Fail(err)
	}
	client, _ := initTencentClient(record, api)
	dnsRequest := dnspod.NewCreateRecordRequest()
	dnsRequest.Domain = common.StringPtr(record.Domain)
	dnsRequest.SubDomain = common.StringPtr(record.SubDomain)
	dnsRequest.RecordType = common.StringPtr(record.RecordType)
	dnsRequest.RecordLine = common.StringPtr(record.RecordLine)
	dnsRequest.Value = common.StringPtr(record.Value)
	response, err := client.CreateRecord(dnsRequest)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		return core.Fail(err)
	}
	if err != nil {
		panic(err)
	}
	logging.Debug("CreateRecord response%s", response.ToJsonString())
	return core.Success(response)
}

func ModifyTencentRecord(record types.DnsRecord) error {
	api, err := GetApiKey("tencent")
	if err != nil {
		return err
	}
	client, _ := initTencentClient(record, api)
	dnsRequest := dnspod.NewModifyRecordRequest()
	dnsRequest.Domain = common.StringPtr(record.Domain)
	dnsRequest.RecordId = common.Uint64Ptr(record.RecordId)
	dnsRequest.RecordType = common.StringPtr(record.RecordType)
	dnsRequest.SubDomain = common.StringPtr(record.SubDomain)
	dnsRequest.Status = common.StringPtr(record.Status)
	dnsRequest.RecordLine = common.StringPtr(record.RecordLine)
	dnsRequest.Value = common.StringPtr(record.Value)

	response, err := client.ModifyRecord(dnsRequest)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		return err
	}
	if err != nil {
		return err
	}
	logging.Debug("ModifyTencentRecord response %s", response.ToJsonString())
	return nil
}

func (m *Wafmaster) ModifyRecord(request *http.Request) core.Response {
	record := types.DnsRecord{}
	if err := core.GetParamsFromRequestToStruct(request, &record); err != nil {
		return core.Fail(err)
	}
	api, err := GetApiKey("tencent")
	if err != nil {
		return core.Fail(err)
	}
	client, _ := initTencentClient(record, api)
	dnsRequest := dnspod.NewModifyRecordRequest()
	dnsRequest.Domain = common.StringPtr(record.Domain)
	dnsRequest.RecordId = common.Uint64Ptr(record.RecordId)
	dnsRequest.RecordType = common.StringPtr(record.RecordType)
	dnsRequest.SubDomain = common.StringPtr(record.SubDomain)
	dnsRequest.Status = common.StringPtr(record.Status)
	dnsRequest.RecordLine = common.StringPtr(record.RecordLine)
	dnsRequest.Value = common.StringPtr(record.Value)
	response, err := client.ModifyRecord(dnsRequest)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		return core.Fail(err)
	}
	if err != nil {
		panic(err)
	}
	return core.Success(response)
}

func (m *Wafmaster) DeleteRecord(request *http.Request) core.Response {
	record := types.DnsRecord{}
	if err := core.GetParamsFromRequestToStruct(request, &record); err != nil {
		return core.Fail(err)
	}
	api, err := GetApiKey("tencent")
	if err != nil {
		return core.Fail(err)
	}
	client, _ := initTencentClient(record, api)

	dnsRequest := dnspod.NewDeleteRecordRequest()
	dnsRequest.Domain = common.StringPtr(record.Domain)
	dnsRequest.RecordId = common.Uint64Ptr(record.RecordId)
	response, err := client.DeleteRecord(dnsRequest)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		return core.Fail(err)
	}
	if err != nil {
		logging.Debug("删除域名解析记录失败: %s", err)
	}
	return core.Success(response)
}

func GetAliyunDnsRecord(domain string) (*alidns20150109.DescribeDomainRecordsResponse, error) {
	api, err := GetApiKey("aliyun")
	if err != nil {
		return nil, err
	}
	client, err := CreateClient(&api.SecretId, &api.SecretKey)
	if err != nil {
		return nil, err
	}
	describeDomainRecordsRequest := &alidns20150109.DescribeDomainRecordsRequest{
		DomainName: tea.String(domain),
		PageNumber: tea.Int64(1),
		PageSize:   tea.Int64(500),
	}

	runtime := &util.RuntimeOptions{}
	result, tryErr := func() (_result *alidns20150109.DescribeDomainRecordsResponse, _e error) {
		defer func() {
			if r := tea.Recover(recover()); r != nil {
				_e = r
			}
		}()
		_result, _err := client.DescribeDomainRecordsWithOptions(describeDomainRecordsRequest, runtime)
		if _err != nil {
			return _result, _err
		}

		return _result, nil
	}()

	if tryErr != nil {
		var error = &tea.SDKError{}
		if _t, ok := tryErr.(*tea.SDKError); ok {
			error = _t
		} else {
			error.Message = tea.String(tryErr.Error())
		}
		var data interface{}
		d := json.NewDecoder(strings.NewReader(tea.StringValue(error.Data)))
		d.Decode(&data)
		if m, ok := data.(map[string]interface{}); ok {
			recommend, _ := m["Recommend"]
			fmt.Println(recommend)
		}
		_, _err := util.AssertAsString(error.Message)
		if _err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (m *Wafmaster) GetAliyunDnsRecord(request *http.Request) core.Response {
	record := types.DnsRecord{}
	if err := core.GetParamsFromRequestToStruct(request, &record); err != nil {
		return core.Fail(err)
	}
	api, err := GetApiKey("aliyun")
	if err != nil {
		return core.Fail(err)
	}
	client, err := CreateClient(&api.SecretId, &api.SecretKey)
	if err != nil {
		return core.Fail(err)
	}
	describeDomainRecordsRequest := &alidns20150109.DescribeDomainRecordsRequest{
		DomainName: tea.String(record.Domain),
		PageNumber: tea.Int64(1),
		PageSize:   tea.Int64(500),
	}

	runtime := &util.RuntimeOptions{}
	result, tryErr := func() (_result *alidns20150109.DescribeDomainRecordsResponse, _e error) {
		defer func() {
			if r := tea.Recover(recover()); r != nil {
				_e = r
			}
		}()
		_result, _err := client.DescribeDomainRecordsWithOptions(describeDomainRecordsRequest, runtime)
		if _err != nil {
			return _result, _err
		}

		return _result, nil
	}()

	if tryErr != nil {
		var error = &tea.SDKError{}
		if _t, ok := tryErr.(*tea.SDKError); ok {
			error = _t
		} else {
			error.Message = tea.String(tryErr.Error())
		}
		var data interface{}
		d := json.NewDecoder(strings.NewReader(tea.StringValue(error.Data)))
		d.Decode(&data)
		if m, ok := data.(map[string]interface{}); ok {
			recommend, _ := m["Recommend"]
			fmt.Println(recommend)
		}
		_, _err := util.AssertAsString(error.Message)
		if _err != nil {
			return core.Fail(_err)
		}
	}
	return core.Success(result)
}

func CreateAliyunRecord(client *alidns20150109.Client, record types.DnsRecord) error {
	ttl := public.InterfaceToInt64(record.TTL)
	addDomainRecordRequest := &alidns20150109.AddDomainRecordRequest{
		DomainName: tea.String(record.Domain),
		RR:         tea.String(record.SubDomain),
		Type:       tea.String(record.RecordType),
		Value:      tea.String(record.Value),
		TTL:        tea.Int64(ttl),
		Line:       tea.String(record.RecordLine),
	}
	runtime := &util.RuntimeOptions{}
	tryErr := func() (_e error) {
		defer func() {
			if r := tea.Recover(recover()); r != nil {
				_e = r
			}
		}()
		_, _err := client.AddDomainRecordWithOptions(addDomainRecordRequest, runtime)
		if _err != nil {
			return _err
		}

		return nil
	}()

	if tryErr != nil {
		var error = &tea.SDKError{}
		if _t, ok := tryErr.(*tea.SDKError); ok {
			error = _t
		} else {
			error.Message = tea.String(tryErr.Error())
		}
		var data interface{}
		d := json.NewDecoder(strings.NewReader(tea.StringValue(error.Data)))
		d.Decode(&data)
		if m, ok := data.(map[string]interface{}); ok {
			recommend, _ := m["Recommend"]
			fmt.Println(recommend)
		}
		_, _err := util.AssertAsString(error.Message)
		if _err != nil {
			return _err
		}
	}
	return nil
}

func (m *Wafmaster) CreateAliyunRecord(request *http.Request) core.Response {
	record := types.DnsRecord{}
	if err := core.GetParamsFromRequestToStruct(request, &record); err != nil {
		return core.Fail(err)
	}
	api, err := GetApiKey("aliyun")
	if err != nil {
		return core.Fail(err)
	}
	client, err := CreateClient(&api.SecretId, &api.SecretKey)
	if err != nil {
		return core.Fail(err)
	}

	addDomainRecordRequest := &alidns20150109.AddDomainRecordRequest{
		DomainName: tea.String(record.Domain),
		RR:         tea.String(record.SubDomain),
		Type:       tea.String(record.RecordType),
		Value:      tea.String(record.Value),
		TTL:        tea.Int64(600),
		Line:       tea.String(record.RecordLine),
	}
	runtime := &util.RuntimeOptions{}
	tryErr := func() (_e error) {
		defer func() {
			if r := tea.Recover(recover()); r != nil {
				_e = r
			}
		}()
		_, _err := client.AddDomainRecordWithOptions(addDomainRecordRequest, runtime)
		if _err != nil {
			return _err
		}

		return nil
	}()

	if tryErr != nil {
		var error = &tea.SDKError{}
		if _t, ok := tryErr.(*tea.SDKError); ok {
			error = _t
		} else {
			error.Message = tea.String(tryErr.Error())
		}
		var data interface{}
		d := json.NewDecoder(strings.NewReader(tea.StringValue(error.Data)))
		d.Decode(&data)
		if m, ok := data.(map[string]interface{}); ok {
			recommend, _ := m["Recommend"]
			fmt.Println(recommend)
		}
		_, _err := util.AssertAsString(error.Message)
		if _err != nil {
			return core.Fail(_err)
		}
	}
	return core.Success(nil)
}

func ModifyAliyunRecordStatus(client *alidns20150109.Client, recordId string, status string) error {
	setDomainRecordStatusRequest := &alidns20150109.SetDomainRecordStatusRequest{
		RecordId: tea.String(recordId),
		Status:   tea.String(status),
	}
	runtime := &util.RuntimeOptions{}
	tryErr := func() (_e error) {
		defer func() {
			if r := tea.Recover(recover()); r != nil {
				_e = r
			}
		}()
		_, _err := client.SetDomainRecordStatusWithOptions(setDomainRecordStatusRequest, runtime)
		if _err != nil {
			return _err
		}

		return nil
	}()

	if tryErr != nil {
		var error = &tea.SDKError{}
		if _t, ok := tryErr.(*tea.SDKError); ok {
			error = _t
		} else {
			error.Message = tea.String(tryErr.Error())
		}
		var data interface{}
		d := json.NewDecoder(strings.NewReader(tea.StringValue(error.Data)))
		d.Decode(&data)
		if m, ok := data.(map[string]interface{}); ok {
			recommend, _ := m["Recommend"]
			fmt.Println(recommend)
		}
		_, _err := util.AssertAsString(error.Message)
		if _err != nil {
			return _err
		}
	}
	return nil
}

func ModifyAliyunRecord(record types.DnsRecord, recordId string) error {
	api, err := GetApiKey("aliyun")
	if err != nil {
		return err
	}
	client, err := CreateClient(&api.SecretId, &api.SecretKey)
	if err != nil {
		return err
	}
	ttl := public.InterfaceToInt64(record.TTL)
	updateDomainRecordRequest := &alidns20150109.UpdateDomainRecordRequest{
		RecordId: tea.String(recordId),
		RR:       tea.String(record.SubDomain),
		Type:     tea.String(record.RecordType),
		Value:    tea.String(record.Value),
		TTL:      tea.Int64(ttl),
		Line:     tea.String(record.RecordLine),
	}
	runtime := &util.RuntimeOptions{}
	tryErr := func() (_e error) {
		defer func() {
			if r := tea.Recover(recover()); r != nil {
				_e = r
			}
		}()
		_, _err := client.UpdateDomainRecordWithOptions(updateDomainRecordRequest, runtime)
		if _err != nil {
			return _err
		}

		return nil
	}()

	if tryErr != nil {
		var error = &tea.SDKError{}
		if _t, ok := tryErr.(*tea.SDKError); ok {
			error = _t
		} else {
			error.Message = tea.String(tryErr.Error())
		}
		var data interface{}
		d := json.NewDecoder(strings.NewReader(tea.StringValue(error.Data)))
		d.Decode(&data)
		if m, ok := data.(map[string]interface{}); ok {
			recommend, _ := m["Recommend"]
			fmt.Println(recommend)
		}
		_, _err := util.AssertAsString(error.Message)
		if _err != nil {
			return err
		}
	}
	return nil
}

func (m *Wafmaster) ModifyAliyunRecord(request *http.Request) core.Response {
	record := types.DnsRecord{}
	if err := core.GetParamsFromRequestToStruct(request, &record); err != nil {
		return core.Fail(err)
	}
	api, err := GetApiKey("aliyun")
	if err != nil {
		return core.Fail(err)
	}
	client, err := CreateClient(&api.SecretId, &api.SecretKey)
	if err != nil {
		return core.Fail(err)
	}
	recordId := public.InterfaceToString(record.RecordId)
	ttl := public.InterfaceToInt64(record.TTL)
	updateDomainRecordRequest := &alidns20150109.UpdateDomainRecordRequest{
		RecordId: tea.String(recordId),
		RR:       tea.String(record.SubDomain),
		Type:     tea.String(record.RecordType),
		Value:    tea.String(record.Value),
		TTL:      tea.Int64(ttl),
		Line:     tea.String(record.RecordLine),
	}
	runtime := &util.RuntimeOptions{}
	tryErr := func() (_e error) {
		defer func() {
			if r := tea.Recover(recover()); r != nil {
				_e = r
			}
		}()
		_, _err := client.UpdateDomainRecordWithOptions(updateDomainRecordRequest, runtime)
		if _err != nil {
			return _err
		}

		return nil
	}()

	if tryErr != nil {
		var error = &tea.SDKError{}
		if _t, ok := tryErr.(*tea.SDKError); ok {
			error = _t
		} else {
			error.Message = tea.String(tryErr.Error())
		}
		var data interface{}
		d := json.NewDecoder(strings.NewReader(tea.StringValue(error.Data)))
		d.Decode(&data)
		if m, ok := data.(map[string]interface{}); ok {
			recommend, _ := m["Recommend"]
			fmt.Println(recommend)
		}
		_, _err := util.AssertAsString(error.Message)
		if _err != nil {
			return core.Fail(_err)
		}
	}
	return core.Success(nil)
}

func (m *Wafmaster) DeleteAliyunRecord(request *http.Request) core.Response {
	record := types.DnsRecord{}
	if err := core.GetParamsFromRequestToStruct(request, &record); err != nil {
		return core.Fail(err)
	}
	api, err := GetApiKey("aliyun")
	if err != nil {
		return core.Fail(err)
	}
	client, err := CreateClient(&api.SecretId, &api.SecretKey)
	if err != nil {
		return core.Fail(err)
	}

	recordId := public.InterfaceToString(record.RecordId)
	deleteDomainRecordRequest := &alidns20150109.DeleteDomainRecordRequest{
		RecordId: tea.String(recordId),
	}
	runtime := &util.RuntimeOptions{}
	tryErr := func() (_e error) {
		defer func() {
			if r := tea.Recover(recover()); r != nil {
				_e = r
			}
		}()
		_, _err := client.DeleteDomainRecordWithOptions(deleteDomainRecordRequest, runtime)
		if _err != nil {
			return _err
		}

		return nil
	}()

	if tryErr != nil {
		var error = &tea.SDKError{}
		if _t, ok := tryErr.(*tea.SDKError); ok {
			error = _t
		} else {
			error.Message = tea.String(tryErr.Error())
		}
		var data interface{}
		d := json.NewDecoder(strings.NewReader(tea.StringValue(error.Data)))
		d.Decode(&data)
		if m, ok := data.(map[string]interface{}); ok {
			recommend, _ := m["Recommend"]
			fmt.Println(recommend)
		}
		_, _err := util.AssertAsString(error.Message)
		if _err != nil {
			return core.Fail(_err)
		}
	}
	return core.Success(nil)
}

func GetTencentDnsRecord(domain string) (*dnspod.DescribeRecordListResponse, error) {
	record := types.DnsRecord{}
	api, err := GetApiKey("tencent")
	if err != nil {
		return nil, err
	}
	client, _ := initTencentClient(record, api)
	dnsRequest := dnspod.NewDescribeRecordListRequest()
	dnsRequest.Domain = common.StringPtr(domain)
	response, err := client.DescribeRecordList(dnsRequest)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (m *Wafmaster) GetDnsRecord(request *http.Request) core.Response {
	record := types.DnsRecord{}
	if err := core.GetParamsFromRequestToStruct(request, &record); err != nil {
		return core.Fail(err)
	}
	api, err := GetApiKey("tencent")
	if err != nil {
		return core.Fail(err)
	}
	client, _ := initTencentClient(record, api)
	dnsRequest := dnspod.NewDescribeRecordListRequest()
	dnsRequest.Domain = common.StringPtr(record.Domain)
	response, err := client.DescribeRecordList(dnsRequest)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		return core.Fail(err)
	}
	if err != nil {
		panic(err)
	}
	return core.Success(response)
}

func SetDnsDomainStatus(domain string, status string) error {

	record := types.DnsRecord{}

	api, err := GetApiKey("tencent")
	if err != nil {
		return err
	}
	client, _ := initTencentClient(record, api)
	request := dnspod.NewModifyDomainStatusRequest()
	request.Domain = common.StringPtr(domain)
	request.Status = common.StringPtr(status)

	_, err = client.ModifyDomainStatus(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		return err
	}
	if err != nil {
		return err
	}
	return nil
}

func _getTencentDnsList() (map[string]bool, error) {
	tenentResponse := make(map[string]bool, 0)
	record := types.DnsRecord{}
	api, err := GetApiKey("tencent")
	if err != nil {
		return tenentResponse, err
	}
	client, _ := initTencentClient(record, api)
	dnsRequest := dnspod.NewDescribeDomainListRequest()
	response, err := client.DescribeDomainList(dnsRequest)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		return tenentResponse, err
	}
	if err != nil {
		return tenentResponse, err
	}

	for _, domain := range response.Response.DomainList {
		dnsStatus := true
		if *domain.DNSStatus == "DNSERROR" {
			dnsStatus = false
		}
		tenentResponse[*domain.Name] = dnsStatus
	}
	return tenentResponse, nil
}

func GetRootDomain(domain string) string {
	rootDomain := ""
	parts := strings.Split(domain, ".")
	rootDomain = strings.Join(parts[len(parts)-2:], ".")
	return rootDomain
}

func GetDomainAndIp(domain []string) (map[string]string, map[string]string) {
	domainMap := make(map[string]string)
	ipMap := make(map[string]string, 0)
	for _, address := range domain {
		address = ReplaceHttp(address)
		if strings.HasPrefix(address, "*.") {
			address = strings.Replace(address, "*.", "", 1)
		}
		if strings.Contains(address, ":") {
			ipSplit := strings.Split(address, ":")
			address = ipSplit[0]
		}
		if IsStringValid(address) && CheckIp(address) {
			ipMap[address] = "1"
		} else {
			rootDomain := GetRootDomain(address)
			if rootDomain != "" {
				domainMap[rootDomain] = "1"
			}
		}
	}
	return domainMap, ipMap
}

func (m *Wafmaster) CheckDnsDomain(request *http.Request) core.Response {
	params := struct {
		Domains []string `json:"domains"`
		Types   string   `json:"types"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	_, _, _, errr := CheckDomainIp(params.Domains, true)
	if errr != nil && errr.Error() != "3" {
		switch errr.Error() {
		case "0":
			return core.Fail("防护域名端口不正确,端口范围为1-65535")
		case "1", "2":
			return core.Fail("防护域名地址不正确" + types.ErrIpWithNotHttp)
		}
		return core.Fail(errr)
	}
	domainMap, _ := GetDomainAndIp(params.Domains)
	allDndResponse := make(map[string]interface{}, 0)
	result := make(map[string]map[string]bool, 0)
	tenentResponse := make(map[string]bool, 0)
	allDndResponse["domainMap"] = domainMap
	api, err := GetApiKey(params.Types)
	if err != nil {
		return core.Fail(err)
	}
	if params.Types == "tencent" {
		tenentResponse, _ = _getTencentDnsList()
		for k, _ := range domainMap {
			if _, ok := result[k]; !ok {
				result[k] = make(map[string]bool, 0)
			}
			if _, ok := tenentResponse[k]; ok {
				result[k]["add_status"] = true
				result[k]["dns_status"] = tenentResponse[k]
			} else {
				result[k]["add_status"] = false
				result[k]["dns_status"] = false
			}
		}

	}
	if params.Types == "aliyun" {
		client, err := CreateClient(&api.SecretId, &api.SecretKey)
		if err != nil {
			return core.Fail(err)
		}
		data, err := _getAliyunDnsList(client)
		if err != nil {
			return core.Fail(err)
		}
		aliyunDomains := make(map[string]bool, 0)
		for _, v := range data.Body.Domains.Domain {
			aliyunDomains[*v.DomainName] = GetAliyunDomainDns(client, *v.DomainName)
			for k, _ := range domainMap {
				if _, ok := result[k]; !ok {
					result[k] = make(map[string]bool, 0)
				}
				if _, ok := aliyunDomains[k]; ok {
					result[k]["add_status"] = true
					result[k]["dns_status"] = aliyunDomains[k]
				} else {
					result[k]["add_status"] = false
					result[k]["dns_status"] = false
				}
			}
		}
	}
	return core.Success(result)
}

func (m *Wafmaster) DeleteDnsRecord(request *http.Request) core.Response {
	params := struct {
		NameList []string `json:"name_list"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}

	if len(params.NameList) == 0 {
		return core.Fail("规则名称不能为空")
	}
	for _, name := range params.NameList {
		if !public.M("dns_info").Where("dns_name =? ", []any{name}).Exists() {
			return core.Fail("规则名称[" + englishToChinese[name] + "]不存在")
		}
		if public.M("load_balance").Where("dns_name =? ", []any{name}).Exists() {
			return core.Fail("规则名称[" + englishToChinese[name] + "]正在被使用，请解除与负载均衡分组的绑定后再删除！")
		}
	}
	_, err := public.MySqlWithClose(func(conn *db.MySql) (res any, err error) {
		conn.Begin()
		defer func() {
			if err != nil {
				conn.Rollback()
				return
			}
			conn.Commit()
		}()
		for _, name := range params.NameList {
			_, err = conn.NewQuery().Table("dns_info").Where("dns_name =? ", []any{name}).Delete()

			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		return core.Fail(fmt.Errorf("删除规则失败：从数据库删除数据失败 %w", err))
	}

	return core.Success("删除成功")
}

func (m *Wafmaster) UpdateDnsRecord(request *http.Request) core.Response {
	api := types.ApiKey{}
	if err := core.GetParamsFromRequestToStruct(request, &api); err != nil {
		return core.Fail(err)
	}
	if !public.M("dns_info").Where("dns_name = ?", []any{api.Types}).Exists() {
		return core.Fail("规则名称[" + englishToChinese[api.Types] + "]不存在")
	}

	query := public.M("dns_info").
		Field([]string{"id", "dns_name", "status", "api_key", "domains", "ps", "create_time"}).
		Order("create_time", "desc")
	query.Where("dns_name = ?", []any{api.Types})
	result, err := query.Find()
	if err != nil {
		return core.Fail(err)
	}
	if api.SecretId != "" && api.SecretKey != "" {
		api.Status = result["status"].(int64)
		switch api.Types {
		case "tencent":
			record := types.DnsRecord{}
			client, err := initTencentClient(record, api)
			if err != nil {
				return core.Fail(err)
			}
			dnsRequest := dnspod.NewDescribePackageDetailRequest()
			_, err = client.DescribePackageDetail(dnsRequest)
			if _, ok := err.(*errors.TencentCloudSDKError); ok {
				return core.Fail("密钥验证不通过，请检查密钥！")
			}
			if err != nil {
				return core.Fail(err)
			}
		case "aliyun":
			client, err := CreateClient(&api.SecretId, &api.SecretKey)
			if err != nil {
				return core.Fail(err)
			}
			_, err = _getAliyunDnsList(client)
			if err != nil {
				return core.Fail(err)
			}
		}
	} else {
		sourceApi, err := GetApiKey(api.Types)
		if err != nil {
			return core.Fail(err)
		}
		api.SecretId = sourceApi.SecretId
		api.SecretKey = sourceApi.SecretKey
	}
	domainString := result["domains"].(string)
	if len(api.DomainList) > 0 {
		domainString = ""
		domainMap := make(map[string]string, 0)
		for _, domain := range api.DomainList {
			domainMap[domain] = "1"

		}
		for k, _ := range domainMap {
			domainString = domainString + k + ","
		}

	}
	ps := result["ps"].(string)
	if api.Ps != "" {
		ps = api.Ps
	}
	status := result["status"].(int64)
	if api.Status != result["status"].(int64) {
		status = api.Status
	}
	api, err = encryptApiKey(api)
	if err != nil {
		return core.Fail(err)
	}

	apiString, err := json.Marshal(api)
	if err != nil {
		return core.Fail(err)
	}
	inDnsData := types.EntryDnsData{
		Key:        string(apiString),
		Name:       api.Types,
		DomainList: domainString,
		Ps:         ps,
		Status:     status,
		Time:       result["create_time"].(int64),
	}
	updateData := public.StructToMap(inDnsData)
	_, err = public.MySqlWithClose(func(conn *db.MySql) (res any, err error) {
		conn.Begin()
		defer func() {
			if err != nil {
				conn.Rollback()
				return
			}
			conn.Commit()
		}()
		_, err = conn.NewQuery().Table("dns_info").
			Where("dns_name = ?", []any{api.Types}).
			Update(updateData)

		if err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return core.Fail(fmt.Errorf("编辑规则失败：数据库更新失败 %w", err))
	}
	public.WriteOptLog(fmt.Sprintf(englishToChinese[api.Types]+"接管更新成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("更新成功")

}

func (m *Wafmaster) GetDnsManufacturerList(request *http.Request) core.Response {
	return m.getDnsManufacturerListV2(request)

	params := struct {
		Types string `json:"types"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	nameSlice := []map[string]any{
		{
			"label":  "阿里云",
			"value":  "aliyun",
			"method": []map[string]string{{"name": "dns", "chinese_name": "DNS轮询"}},
		},
		{
			"label":  "腾讯云",
			"value":  "tencent",
			"method": []map[string]string{{"name": "dns", "chinese_name": "DNS轮询"}},
		},
	}
	if params.Types == "" {
		nameSlice = make([]map[string]any, 0)
		if public.M("dns_info").Where("dns_name = ? and status = ?", []any{"aliyun", 1}).Exists() {
			nameSlice = append(nameSlice, map[string]any{
				"label":  "阿里云",
				"value":  "aliyun",
				"method": []map[string]string{{"name": "dns", "chinese_name": "DNS轮询"}},
			})
		}
		if public.M("dns_info").Where("dns_name = ? and status = ?", []any{"tencent", 1}).Exists() {
			nameSlice = append(nameSlice, map[string]any{
				"label":  "腾讯云",
				"value":  "tencent",
				"method": []map[string]string{{"name": "dns", "chinese_name": "DNS轮询"}},
			})
		}
		nameSlice = append(nameSlice, map[string]any{
			"label":  "不设置",
			"value":  "",
			"method": []map[string]string{{"name": "", "chinese_name": ""}},
		})
	}
	return core.Success(map[string]any{
		"name": nameSlice,
	})
}

func (m *Wafmaster) getDnsManufacturerListV2(request *http.Request) core.Response {
	params := struct {
		Types string `json:"types"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	res := make([]map[string]any, 0, 256)
	switch params.Types {
	case "dns":
		res = append(res, map[string]any{
			"label":  "阿里云",
			"value":  "aliyun",
			"method": []map[string]string{{"name": "dns", "chinese_name": "DNS轮询"}},
		}, map[string]any{
			"label":  "腾讯云",
			"value":  "tencent",
			"method": []map[string]string{{"name": "dns", "chinese_name": "DNS轮询"}},
		})
	default:
		dnsList := make([]struct {
			DnsName string `json:"dns_name"`
			Ps      string `json:"ps"`
		}, 0, 256)

		if err := public.M("dns_info").Where("status", 1).Field([]string{"dns_name", "ps"}).SelectAs(&dnsList); err != nil {
			return core.Fail(fmt.Errorf("获取DNS托管商列表失败：%w", err))
		}

		for _, v := range dnsList {
			label := ""
			switch v.DnsName {
			case "aliyun":
				label = "阿里云"

				if v.Ps != "" {
					label += "(" + v.Ps + ")"
				}
				res = append(res, map[string]any{
					"label":  label,
					"value":  "aliyun",
					"method": []map[string]string{{"name": "dns", "chinese_name": "DNS轮询"}},
				})
			case "tencent":
				label = "腾讯云"

				if v.Ps != "" {
					label += "(" + v.Ps + ")"
				}

				res = append(res, map[string]any{
					"label":  label,
					"value":  "tencent",
					"method": []map[string]string{{"name": "dns", "chinese_name": "DNS轮询"}},
				})
			}
		}

		res = append(res, map[string]any{
			"label":  "不设置",
			"value":  "",
			"method": []map[string]string{{"name": "", "chinese_name": ""}},
		})
	}

	return core.Success(map[string]any{
		"name": res,
	})
}

func _getAliyunDnsList(client *alidns20150109.Client) (_result *alidns20150109.DescribeDomainsResponse, _err error) {
	describeDomainsRequest := &alidns20150109.DescribeDomainsRequest{}
	runtime := &util.RuntimeOptions{}
	result, tryErr := func() (_result *alidns20150109.DescribeDomainsResponse, _e error) {
		defer func() {
			if r := tea.Recover(recover()); r != nil {
				_e = r
			}
		}()
		data, _err := client.DescribeDomainsWithOptions(describeDomainsRequest, runtime)
		if _err != nil {
			return nil, _err
		}
		return data, nil
	}()

	if tryErr != nil {
		var error = &tea.SDKError{}
		if _t, ok := tryErr.(*tea.SDKError); ok {
			error = _t
		} else {
			error.Message = tea.String(tryErr.Error())
		}
		var data interface{}
		d := json.NewDecoder(strings.NewReader(tea.StringValue(error.Data)))
		d.Decode(&data)
		if m, ok := data.(map[string]interface{}); ok {
			recommend, _ := m["Recommend"]
			logging.Debug("recommend:", recommend)
			return nil, err.New("api密钥验证不通过，请检查密钥！")
		}
		_, _err = util.AssertAsString(error.Message)
		if _err != nil {
			return nil, _err
		}
	}
	return result, nil
}

func GetAliyunDnsList(client *alidns20150109.Client) int64 {
	var parseNumber int64
	describeDomainsRequest := &alidns20150109.DescribeDomainsRequest{}
	runtime := &util.RuntimeOptions{}
	resultNum, tryErr := func() (resultNum int64, _e error) {
		defer func() {
			if r := tea.Recover(recover()); r != nil {
				_e = r
			}
		}()
		result, _err := client.DescribeDomainsWithOptions(describeDomainsRequest, runtime)
		if _err != nil {
			return parseNumber, _err
		}

		return *result.Body.TotalCount, nil
	}()

	if tryErr != nil {
		var error = &tea.SDKError{}
		if _t, ok := tryErr.(*tea.SDKError); ok {
			error = _t
		} else {
			error.Message = tea.String(tryErr.Error())
		}
		var data interface{}
		d := json.NewDecoder(strings.NewReader(tea.StringValue(error.Data)))
		d.Decode(&data)
		if m, ok := data.(map[string]interface{}); ok {
			recommend, _ := m["Recommend"]
			fmt.Println(recommend)
		}
		_, _err := util.AssertAsString(error.Message)
		if _err != nil {
			return 0
		}
	}
	return resultNum
}

func GetAliyunDomainDns(client *alidns20150109.Client, domain string) bool {
	describeDomainNsRequest := &alidns20150109.DescribeDomainNsRequest{
		DomainName: tea.String(domain),
	}
	runtime := &util.RuntimeOptions{}
	e := err.New("1")
	boolV, tryErr := func(_e error) (bool, error) {
		defer func() {
			if r := tea.Recover(recover()); r != nil {
				_e = r
			}
		}()
		result, _err := client.DescribeDomainNsWithOptions(describeDomainNsRequest, runtime)
		if _err != nil {
			return false, _err
		}
		return *result.Body.IncludeAliDns, nil
	}(e)
	return boolV
	if tryErr != nil {
		var error = &tea.SDKError{}
		if _t, ok := tryErr.(*tea.SDKError); ok {
			error = _t
		} else {
			error.Message = tea.String(tryErr.Error())
		}

		fmt.Println(tea.StringValue(error.Message))

		var data interface{}
		d := json.NewDecoder(strings.NewReader(tea.StringValue(error.Data)))
		d.Decode(&data)
		if m, ok := data.(map[string]interface{}); ok {
			recommend, _ := m["Recommend"]
			fmt.Println(recommend)
		}
		_, _err := util.AssertAsString(error.Message)
		if _err != nil {
			return false
		}
	}
	return false
}

func _getAliyunDomainParseList(client *alidns20150109.Client, domain string, pageSize int64, pageNumber int64) (*alidns20150109.DescribeDomainRecordsResponse, error) {
	describeDomainRecordsRequest := &alidns20150109.DescribeDomainRecordsRequest{
		DomainName: tea.String(domain),
		PageSize:   tea.Int64(pageSize),
		PageNumber: tea.Int64(pageNumber),
	}
	runtime := &util.RuntimeOptions{}
	result, tryErr := func() (_result *alidns20150109.DescribeDomainRecordsResponse, _e error) {
		defer func() {
			if r := tea.Recover(recover()); r != nil {
				_e = r
			}
		}()
		dnsResult, _err := client.DescribeDomainRecordsWithOptions(describeDomainRecordsRequest, runtime)
		if _err != nil {
			return nil, _err
		}
		return dnsResult, nil
	}()

	if tryErr != nil {
		var error = &tea.SDKError{}
		if _t, ok := tryErr.(*tea.SDKError); ok {
			error = _t
		} else {
			error.Message = tea.String(tryErr.Error())
		}
		var data interface{}
		d := json.NewDecoder(strings.NewReader(tea.StringValue(error.Data)))
		d.Decode(&data)
		if m, ok := data.(map[string]interface{}); ok {
			recommend, _ := m["Recommend"]
			fmt.Println(recommend)
		}
		_, _err := util.AssertAsString(error.Message)
		if _err != nil {
			return nil, _err
		}
	}
	return result, nil
}

func (m *Wafmaster) GetDnsDomainList(request *http.Request) core.Response {
	params := struct {
		P       int64  `json:"p"`
		PSize   int    `json:"p_size"`
		Keyword string `json:"keyword"`
		Types   string `json:"types"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}
	query := public.M("dns_info").
		Field([]string{"dns_name", "status", "api_key"}).
		Where("dns_name = ?", []any{params.Types})
	result, err := query.Find()
	if err != nil {
		return core.Fail(err)
	}
	if result == nil {
		return core.Fail(fmt.Errorf("请先配置该厂商DNS接管"))
	}

	api := types.ApiKey{}
	if err := json.Unmarshal([]byte(result["api_key"].(string)), &api); err != nil {
		return core.Fail(fmt.Errorf("获取列表失败：%w", err))
	}
	api, err = decryptApiKey(api)
	if err != nil {
		return core.Fail(err)
	}
	ListData := make([]types.DnsDomainInfo, 0)
	switch params.Types {
	case "aliyun":
		client, err := CreateClient(&api.SecretId, &api.SecretKey)
		if err != nil {
			return core.Fail(err)
		}
		data, err := _getAliyunDnsList(client)
		if err != nil {
			return core.Fail(err)
		}

		for _, v := range data.Body.Domains.Domain {
			dnsData := types.DnsDomainInfo{}
			dnsData.DnsName = "aliyun"
			dnsData.RootDomain = *v.DomainName
			if params.Keyword != "" && !strings.Contains(*v.DomainName, params.Keyword) {
				continue
			}
			dnsData.ChineseName = englishToChinese[params.Types]
			dnsData.Status = 0
			dnsData.ParseList = make([]interface{}, 0)
			dnsData.Version = *v.VersionCode
			if _, ok := aliyunVersion[*v.VersionCode]; ok {
				dnsData.Version = aliyunVersion[*v.VersionCode]
			}

			if dnsData.Subdomain == nil {
				dnsData.Subdomain = make(map[string]string, 0)
			}
			dnsData.DnsServer = GetAliyunDomainDns(client, *v.DomainName)
			if dnsData.DnsServer {
				pageSize := 500
				response, err := _getAliyunDomainParseList(client, *v.DomainName, int64(pageSize), 1)
				if err != nil {
					ListData = append(ListData, dnsData)
					continue
				}

				for i := 2; i <= 100; i++ {
					addResponse := response
					if public.InterfaceToInt(*addResponse.Body.TotalCount) > pageSize*(i-1) {
						addResponse, err := _getAliyunDomainParseList(client, *v.DomainName, int64(pageSize), int64(i))
						if err != nil {
							continue
						}
						for _, vv := range addResponse.Body.DomainRecords.Record {
							response.Body.DomainRecords.Record = append(response.Body.DomainRecords.Record, vv)
						}
					} else {
						break
					}
				}
				for _, v1 := range response.Body.DomainRecords.Record {
					dnsParse := &types.AliyunParse{}
					dnsParse.Host = *v1.RR
					dnsParse.Type = *v1.Type
					dnsParse.TTL = *v1.TTL
					if *v1.Status == "ENABLE" {
						dnsParse.Status = 1
					} else {
						dnsParse.Status = 0
					}
					dnsParse.Line = *v1.Line
					if *v1.Type == "MX" && v1.Priority != nil {
						dnsParse.Ip = *v1.Value + " | " + public.InterfaceToString(*v1.Priority)
					} else {
						dnsParse.Ip = *v1.Value
					}
					dnsData.ParseList = append(dnsData.ParseList, *dnsParse)
				}
				ListData = append(ListData, dnsData)
			} else {
				ListData = append(ListData, dnsData)
			}
		}
		return core.Success(map[string]any{
			"total": len(ListData),
			"list":  ListData,
		})
	case "tencent":
		record := types.DnsRecord{}
		client, err := initTencentClient(record, api)
		if err != nil {
			return core.Fail(err)
		}
		domainDnsStatus, _ := _getTencentDnsList()
		dnsRequest := dnspod.NewDescribeDomainListRequest()
		data, err := client.DescribeDomainList(dnsRequest)
		if _, ok := err.(*errors.TencentCloudSDKError); ok {
			return core.Fail("密钥验证不通过，请检查密钥！")
		}
		if err != nil {
			return core.Fail(err)
		}
		if *data.Response.DomainCountInfo.DomainTotal > 0 {
			for _, v := range data.Response.DomainList {
				dnsData := types.DnsDomainInfo{}
				dnsData.RootDomain = *v.Name
				if params.Keyword != "" && !strings.Contains(*v.Name, params.Keyword) {
					continue
				}
				if _, ok := domainDnsStatus[*v.Name]; ok {
					dnsData.DnsServer = domainDnsStatus[*v.Name]
				}
				dnsData.DnsName = "tencent"
				dnsData.ChineseName = englishToChinese[params.Types]
				dnsData.Status = 0
				dnsData.Version = *v.GradeTitle
				dnsData.ParseList = make([]interface{}, 0)
				if dnsData.Subdomain == nil {
					dnsData.Subdomain = make(map[string]string, 0)
				}
				if *v.RecordCount > 0 {
					client, _ = initTencentClient(record, api)
					dnsRequest := dnspod.NewDescribeRecordListRequest()

					dnsRequest.Domain = common.StringPtr(*v.Name)
					response, err := client.DescribeRecordList(dnsRequest)
					if _, ok := err.(*errors.TencentCloudSDKError); ok {
						ListData = append(ListData, dnsData)
						continue
					}
					if err != nil {
						ListData = append(ListData, dnsData)
						continue
					}
					if dnsData.Subdomain == nil {
						dnsData.Subdomain = make(map[string]string, 0)
					}

					for _, v1 := range response.Response.RecordList {
						if strings.Contains(*v1.Value, "dnspod") {
							continue
						}
						if strings.Contains(*v1.Value, "dnspod") {
							continue
						}

						dnsParse := &types.TencentParse{}
						dnsParse.Host = *v1.Name
						dnsParse.Type = *v1.Type
						dnsParse.Ip = *v1.Value
						dnsParse.TTL = *v1.TTL
						dnsParse.Line = *v1.Line
						if *v1.Status == "ENABLE" {
							dnsParse.Status = 1
						} else {
							dnsParse.Status = 0
						}
						if v1.Weight != nil {
							dnsParse.Weight = *v1.Weight
						} else {
							dnsParse.Weight = 0
						}
						dnsData.ParseList = append(dnsData.ParseList, *dnsParse)

					}
					ListData = append(ListData, dnsData)
				} else {
					ListData = append(ListData, dnsData)
				}
			}
			return core.Success(map[string]any{
				"total": len(ListData),
				"list":  ListData,
			})

		}
		return core.Success(map[string]any{
			"total": len(ListData),
			"list":  ListData,
		})

	}
	return core.Success(map[string]any{
		"total": len(ListData),
		"list":  ListData,
	})
}

func GetTencentDnsList() (int, error) {
	record := types.DnsRecord{}
	record.Endpoint = "dnspod.tencentcloudapi.com"
	api, err := GetApiKey("tencent")
	if err != nil {
		return 0, err
	}
	client, _ := initTencentClient(record, api)
	dnsRequest := dnspod.NewDescribeDomainListRequest()
	response, err := client.DescribeDomainList(dnsRequest)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		return 0, err
	}
	if err != nil {
		return 0, err
	}
	return int(*response.Response.DomainCountInfo.DomainTotal), nil
}

func (m *Wafmaster) GetDnsList(request *http.Request) core.Response {
	params := struct {
		Keyword string `json:"keyword"`
		P       int    `json:"p"`
		PSize   int    `json:"p_size"`
		Id      int    `json:"id"`
	}{}

	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(err)
	}

	query := public.M("dns_info").
		Field([]string{"id", "dns_name", "status", "api_key", "domains", "ps", "create_time"}).
		Order("create_time", "desc")
	if params.Keyword != "" {
		query.Where("ps like ?", []any{"%" + params.Keyword + "%"})
	}
	if params.Id != 0 {
		query.Where("id = ?", []any{2})
	}

	res, err := public.SimplePage(query, params)
	if err != nil {
		return core.Fail(fmt.Errorf("获取列表失败：%w", err))
	}
	mm := struct {
		Total int                  `json:"total"`
		List  []*types.ListDnsData `json:"list"`
	}{}

	if err = public.MapToStruct(res, &mm); err != nil {
		return core.Fail(fmt.Errorf("获取列表失败：%w", err))
	}
	api := types.ApiKey{}
	if err = public.MapToStruct(res, &api); err != nil {
		return core.Fail(fmt.Errorf("获取列表失败：%w", err))
	}
	for _, v := range mm.List {
		v.NameChinese = englishToChinese[v.Name]
		api := types.ApiKey{}

		if err := json.Unmarshal([]byte(v.Key), &api); err != nil {
			return core.Fail(fmt.Errorf("获取列表失败：%w", err))
		}
		api, err = decryptApiKey(api)
		if err != nil {
			return core.Fail(err)
		}

		if v.Name == "aliyun" {
			api, err := GetApiKey("aliyun")
			if err != nil {
				continue
			}
			aliyunClient, err := CreateClient(&api.SecretId, &api.SecretKey)
			if err != nil {
				return core.Fail(err)
			}
			v.DomainTotal = int(GetAliyunDnsList(aliyunClient))
		}
		if v.Name == "tencent" {
			v.DomainTotal, _ = GetTencentDnsList()
		}

		inString := "**********"
		domainList := strings.Split(v.DomainList, ",")
		logging.Debug("domainList:", domainList)

		if api.SecretId != "" && api.SecretKey != "" {
			v.Key = api.SecretId[:10] + inString + (api.SecretKey[:10])
		} else {
			v.Key = ""
		}

	}
	mm.Total = len(mm.List)
	return core.Success(mm)
}

func encryptApiKey(api types.ApiKey) (types.ApiKey, error) {
	var err error
	api.SecretId, err = encryption.AesEncrypt(api.SecretId, aesKey)
	if err != nil {
		return api, err
	}
	api.SecretKey, err = encryption.AesEncrypt(api.SecretKey, aesKey)
	if err != nil {
		return api, err
	}
	return api, nil
}

func decryptApiKey(api types.ApiKey) (types.ApiKey, error) {
	var err error
	api.SecretId, err = encryption.AesDecrypt(api.SecretId, aesKey)
	if err != nil {
		return api, err
	}
	api.SecretKey, err = encryption.AesDecrypt(api.SecretKey, aesKey)
	if err != nil {
		return api, err
	}
	return api, nil
}

func (m *Wafmaster) CreateApiKey(request *http.Request) core.Response {
	api := types.ApiKey{}
	if err := core.GetParamsFromRequestToStruct(request, &api); err != nil {
		return core.Fail(err)
	}
	api.SecretId = strings.TrimSpace(api.SecretId)
	api.SecretKey = strings.TrimSpace(api.SecretKey)
	if api.SecretId == "" || api.SecretKey == "" {
		return core.Fail("SecretId和SecretKey都不有为空，请检查输入信息")
	}
	if public.M("dns_info").Where("dns_name = ?", []any{api.Types}).Exists() {
		return core.Fail("规则名称[" + englishToChinese[api.Types] + "]已存在")
	}

	switch api.Types {
	case "tencent":
		record := types.DnsRecord{}
		client, err := initTencentClient(record, api)
		if err != nil {
			return core.Fail(err)
		}
		dnsRequest := dnspod.NewDescribePackageDetailRequest()
		_, err = client.DescribePackageDetail(dnsRequest)
		if _, ok := err.(*errors.TencentCloudSDKError); ok {
			return core.Fail("密钥验证不通过，请检查密钥！")
		}
		if err != nil {
			return core.Fail(err)
		}
	case "aliyun":
		client, err := CreateClient(&api.SecretId, &api.SecretKey)
		if err != nil {
			return core.Fail(err)
		}
		_, err = _getAliyunDnsList(client)
		if err != nil {
			return core.Fail(err)
		}
	}
	api, err := encryptApiKey(api)
	if err != nil {
		return core.Fail(err)
	}

	apiString, err := json.Marshal(api)

	if err != nil {
		return core.Fail(err)
	}
	inDnsData := types.EntryDnsData{
		Key:        string(apiString),
		Name:       api.Types,
		DomainList: "baidu.com,bt.cn",
		Ps:         api.Ps,
		Status:     1,
		Time:       time.Now().Unix(),
	}
	insertData := public.StructToMap(inDnsData)

	_, err = public.MySqlWithClose(func(conn *db.MySql) (res any, err error) {
		conn.Begin()
		defer func() {
			if err != nil {
				conn.Rollback()
				return
			}
			conn.Commit()
		}()
		_, err = conn.NewQuery().Table("dns_info").Insert(insertData)

		if err != nil {
			return nil, err
		}
		return nil, nil
	})
	public.WriteOptLog(fmt.Sprintf(englishToChinese[api.Types]+"接管添加成功"), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success("添加成功")

}

func initTencentClient(record types.DnsRecord, api types.ApiKey) (*dnspod.Client, error) {

	credential := common.NewCredential(
		api.SecretId,
		api.SecretKey,
	)

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = record.Endpoint
	client, err := dnspod.NewClient(credential, record.Region, cpf)
	if err != nil {
		return nil, err

	}
	return client, nil

}

func CreateClient(accessKeyId *string, accessKeySecret *string) (_result *alidns20150109.Client, _err error) {
	config := &openapi.Config{
		AccessKeyId:     accessKeyId,
		AccessKeySecret: accessKeySecret,
	}
	config.Endpoint = tea.String("alidns.cn-shanghai.aliyuncs.com")
	_result = &alidns20150109.Client{}
	_result, _err = alidns20150109.NewClient(config)
	return _result, _err
}

func (m *Wafmaster) GetDnsStatusByDomain(request *http.Request) core.Response {
	record := types.DnsRecord{}
	if err := core.GetParamsFromRequestToStruct(request, &record); err != nil {
		return core.Fail(err)
	}
	api, err := GetApiKey("tencent")
	if err != nil {
		return core.Fail(err)
	}
	client, _ := initTencentClient(record, api)
	dnsRequest := dnspod.NewDescribeDomainRequest()
	dnsRequest.Domain = common.StringPtr(record.Domain)
	response, err := client.DescribeDomain(dnsRequest)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		core.Fail(err)
	}
	if err != nil {
		return core.Fail("获取域名信息失败")
	}
	return core.Success(response.Response)
}

func (m *Wafmaster) GetFreeInfo(request *http.Request) core.Response {

	inputApi := types.ApiKey{}
	api, err := GetApiKey(inputApi.Types)
	if err != nil {
		return core.Fail(err)
	}
	if inputApi.Types == "tencent" {
		record := types.DnsRecord{}
		if err := core.GetParamsFromRequestToStruct(request, &inputApi); err != nil {
			return core.Fail(err)
		}
		client, _ := initTencentClient(record, api)
		dnsRequest := dnspod.NewDescribePackageDetailRequest()
		response, err := client.DescribePackageDetail(dnsRequest)
		if _, ok := err.(*errors.TencentCloudSDKError); ok {
			return core.Fail(err)
		}
		if err != nil {
			panic(err)
		}
		logging.Debug("GetFreeInfo response:%s", response.ToJsonString())
	}
	if inputApi.Types == "aliyun" {

	}
	return core.Success("")
}

func (m *Wafmaster) CreateDomainDnsRecord(request *http.Request) core.Response {

	record := types.DnsRecord{}
	if err := core.GetParamsFromRequestToStruct(request, &record); err != nil {
		return core.Fail(err)
	}
	api, err := GetApiKey("tencent")
	if err != nil {
		return core.Fail(err)
	}
	client, _ := initTencentClient(record, api)

	dnsRequest := dnspod.NewCreateDomainRequest()
	dnsRequest.Domain = common.StringPtr(record.Domain)
	response, err := client.CreateDomain(dnsRequest)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		return core.Fail(err)
	}
	if err != nil {
		panic(err)
	}
	return core.Success(response)
}

type Wafmaster struct{}
type EntryFromDatabase struct {
	Id           int    `json:"id"`
	Name         string `json:"name"`
	Servers      string `json:"servers"`
	CreateTime   int64  `json:"create_time"`
	Priority     int    `json:"priority"`
	Status       int    `json:"status"`
	IsGlobal     int    `json:"is_global"`
	Src          int    `json:"src"`
	ExecutePhase string `json:"execute_phase"`
	Action       string `json:"action"`
	Root         string `json:"root"`
}
