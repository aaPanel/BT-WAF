package modules

import (
	"CloudWaf/core"
	"CloudWaf/public"
	"CloudWaf/public/db"
	"CloudWaf/types"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	loadMethod = map[string]string{"dns": "DNS轮询", "region": "区域分流", "weight": "权重分流"}
)

type Wafmasterload struct{}

func init() {
	core.RegisterModule(&Wafmasterload{})

}

func Transform(data types.MasterLoadBalanceAll) (types.EntryMasterLoadBalance, error) {
	nodesString, err := json.Marshal(data.Nodes)
	if err != nil {

		return types.EntryMasterLoadBalance{}, err
	}
	EntryMasterLoadBalance := types.EntryMasterLoadBalance{
		Name:         data.Name,
		CorruptCheck: data.CorruptCheck,
		DnsName:      data.DnsName,
		Method:       data.Method,
		Nodes:        string(nodesString),
		Ps:           data.Ps,
		CreateTime:   data.CreateTime,
	}
	return EntryMasterLoadBalance, nil
}

func TransformBack(data string) ([]types.LoadNodes, error) {
	var nodes []types.LoadNodes
	if err := json.Unmarshal([]byte(data), &nodes); err != nil {
		return []types.LoadNodes{}, err
	}
	return nodes, nil
}

func (w *Wafmasterload) CreateLoadBalance(request *http.Request) core.Response {
	loadBalance := types.MasterLoadBalanceAll{}
	if err := core.GetParamsFromRequestToStruct(request, &loadBalance); err != nil {
		return core.Fail(err)
	}
	_, err := json.Marshal(loadBalance)
	if err != nil {
		return core.Fail(err)
	}
	err = CreateLoadBalanceByPublic(loadBalance)
	if err != nil {
		return core.Fail(err)
	}

	logString := "负载均衡分组【" + loadBalance.Name + "】添加成功"
	public.WriteOptLog(fmt.Sprintf(logString), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success(logString)
}

func CreateLoadBalanceByPublic(loadBalance types.MasterLoadBalanceAll) error {
	timestamp := time.Now().Unix()
	loadBalance.CreateTime = timestamp
	for _, v := range loadBalance.Nodes {
		v.CreateTime = timestamp
	}
	if len(loadBalance.Nodes) == 0 && loadBalance.Name != "默认分组" {
		return errors.New("节点不能为空")
	}
	if public.M("load_balance").Where("load_name = ?", []any{loadBalance.Name}).Exists() {
		return errors.New("集群名称[" + loadBalance.Name + "已存在")
	}
	inDnsData, err := Transform(loadBalance)
	if err != nil {
		return err
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
		loadBalanceId, err := conn.NewQuery().Table("load_balance").Insert(updateData)
		if loadBalance.Name == "默认分组" {
			_, err := conn.NewQuery().Table("load_balance").Where("id = ?", []any{loadBalanceId}).Update(map[string]any{"id": 1})
			if err != nil {
				return nil, err
			}
		}

		if err != nil {
			return nil, err
		}
		for _, v := range loadBalance.Nodes {
			_, err = conn.NewQuery().Table("cluster_nodes").Where("sid = ?", []any{v.Id}).Update(map[string]any{
				"group_id": loadBalanceId,
			})
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	if err != nil {
		return fmt.Errorf("添加规则失败：数据库插入失败 %w", err)
	}
	return nil
}

func (w *Wafmasterload) ModifyLoadBalance(request *http.Request) core.Response {
	loadBalance := types.MasterLoadBalanceAll{}
	if err := core.GetParamsFromRequestToStruct(request, &loadBalance); err != nil {
		return core.Fail(err)
	}
	if loadBalance.Id == 1 && loadBalance.Name != "默认分组" {
		return core.Fail("默认分组名称不允许修改")
	}
	if !public.M("load_balance").Where("id = ?", []any{loadBalance.Id}).Exists() {
		return core.Fail("集群名称[" + loadBalance.Name + "不存在")
	}
	if len(loadBalance.Nodes) == 0 {
		return core.Fail("节点不能为空")
	}
	srcNodes, err := public.M("load_balance").Field([]string{"nodes"}).Where("id = ?", []any{loadBalance.Id}).Find()
	if err != nil {
		return core.Fail(err)
	}
	srcNodesList, err := TransformBack(srcNodes["nodes"].(string))
	if err != nil {
		return core.Fail(err)
	}
	delNodesList := make([]string, 0)
	for _, srcNode := range srcNodesList {
		delStatus := true
		for _, node := range loadBalance.Nodes {
			if srcNode.Id == node.Id {
				delStatus = false
			}
		}
		if delStatus {
			delNodesList = append(delNodesList, srcNode.Id)
		}
	}
	inDnsData, err := Transform(loadBalance)
	if err != nil {
		return core.Fail(err)
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
		_, err = conn.NewQuery().Table("load_balance").
			Where("id = ?", []any{loadBalance.Id}).
			Update(updateData)

		if err != nil {
			return nil, err
		}
		for _, v := range loadBalance.Nodes {
			_, err = conn.NewQuery().Table("cluster_nodes").Where("sid = ?", []any{v.Id}).Update(map[string]any{
				"group_id": loadBalance.Id,
			})
			if err != nil {
				return nil, err
			}
		}
		for _, v := range delNodesList {
			_, err = conn.NewQuery().Table("cluster_nodes").Where("sid = ?", []any{v}).Update(map[string]any{
				"group_id": 0,
			})
			if err != nil {
				return nil, err
			}
		}
		timestamp := time.Now().Unix()
		conn, err = AddSiteSyncData(conn, loadBalance.Id, "", timestamp)
		if err != nil {
			return nil, err
		}
		return nil, nil
	})

	logString := "负载均衡分组【" + loadBalance.Name + "】编辑成功"
	public.WriteOptLog(fmt.Sprintf(logString), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	return core.Success(logString)
}

func (w *Wafmasterload) DeleteLoadBalance(request *http.Request) core.Response {
	loadBalance := struct {
		LoadList []types.MasterLoadBalanceAll `json:"load_list"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &loadBalance); err != nil {
		return core.Fail(err)
	}
	loadName := make([]string, 0)
	for _, load := range loadBalance.LoadList {
		loadName = append(loadName, load.Name)
		if load.Id == 1 {
			return core.Fail("默认分组不允许删除")
		}
		if !public.M("load_balance").Where("id = ?", []any{load.Id}).Exists() {
			return core.Fail("集群名称[" + load.Name + "不存在")
		}
		if public.M("site_info").Where("load_group_id = ?", []any{load.Id}).Exists() {
			return core.Fail("负载均衡分组[" + load.Name + "]已绑定网站，请先解绑")
		}
	}

	successList := make([]string, 0)
	errorList := make([]string, 0)
	_, err := public.MySqlWithClose(func(conn *db.MySql) (res any, err error) {
		conn.Begin()
		defer func() {
			if err != nil {
				conn.Rollback()
				return
			}
			conn.Commit()
		}()
		for idx, load := range loadBalance.LoadList {
			_, err = conn.NewQuery().Table("load_balance").Where("id = ?", []any{load.Id}).Delete()
			if err != nil {
				errorList = append(errorList, loadName[idx])
			} else {
				successList = append(successList, loadName[idx])
			}
			_, err = public.M("cluster_nodes").Where("group_id =?", []any{load.Id}).Update(map[string]any{"group_id": 0})
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})

	if err != nil {
		return core.Fail(fmt.Errorf("删除规则失败：从数据库删除数据失败 %w", err))
	}
	successLogString := ""
	if len(successList) > 0 {
		successLogString = "负载均衡分组【" + strings.Join(successList, " ") + "】删除成功"
	}
	errorLogString := ""
	if len(errorList) > 0 {
		errorLogString = "负载均衡分组【" + strings.Join(errorList, " ") + "】删除失败"
	}
	if successLogString != "" {
		successLogString = successLogString + "</br>"
	}
	logString := successLogString + errorLogString
	public.WriteOptLog(fmt.Sprintf(logString), public.OPT_LOG_TYPE_SITE_LIST, public.GetUid(request))
	if successLogString != "" {
		return core.Success(logString)
	} else {
		return core.Fail(logString)
	}

}
