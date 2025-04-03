package modules

import (
	"CloudWaf/core"
	"CloudWaf/public"
	"CloudWaf/public/access"
	"fmt"
	"net/http"
)

func init() {
	core.RegisterModule(&Multi{})
}

type Multi struct{}

func (multi *Multi) RoleList(request *http.Request) core.Response {
	return core.Success(access.RbacManager.RoleList(public.GetUid(request)))
}

func (multi *Multi) UpdateRole(request *http.Request) core.Response {
	roleItem := access.RoleItem{}
	if err := core.GetParamsFromRequestToStruct(request, &roleItem); err != nil {
		return core.Fail(fmt.Errorf("获取请求参数失败：%w", err))
	}
	if err := access.RbacManager.UpdateRole(roleItem); err != nil {
		return core.Fail(err)
	}
	return core.Success("操作成功")
}

func (multi *Multi) RemoveRole(request *http.Request) core.Response {
	params := struct {
		RoleIds []int `json:"role_ids"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(fmt.Errorf("获取请求参数失败：%w", err))
	}
	if err := access.RbacManager.RemoveRole(params.RoleIds...); err != nil {
		return core.Fail(err)
	}
	return core.Success("操作成功")
}

func (multi *Multi) UserList(request *http.Request) core.Response {
	return core.Success(access.RbacManager.UserList(public.GetUid(request)))
}

func (multi *Multi) UpdateUser(request *http.Request) core.Response {
	userItem := access.UserItem{}

	if err := core.GetParamsFromRequestToStruct(request, &userItem); err != nil {
		return core.Fail(fmt.Errorf("获取请求参数失败：%w", err))
	}
	if err := access.RbacManager.UpdateUser(userItem); err != nil {
		return core.Fail(err)
	}
	return core.Success("操作成功")
}

func (multi *Multi) UpdateUserPassword(request *http.Request) core.Response {
	userItem := access.UserSecretItem{}
	if err := core.GetParamsFromRequestToStruct(request, &userItem); err != nil {
		return core.Fail(fmt.Errorf("获取请求参数失败：%w", err))
	}
	if err := access.RbacManager.UpdatePassword(userItem); err != nil {
		return core.Fail(err)
	}
	return core.Success("操作成功")
}

func (multi *Multi) RemoveUser(request *http.Request) core.Response {
	params := struct {
		Uids []int `json:"uids"`
	}{}
	if err := core.GetParamsFromRequestToStruct(request, &params); err != nil {
		return core.Fail(fmt.Errorf("获取请求参数失败：%w", err))
	}
	if err := access.RbacManager.RemoveUser(params.Uids...); err != nil {
		return core.Fail(err)
	}
	return core.Success("操作成功")
}

func (multi *Multi) NodeList(request *http.Request) core.Response {
	return core.Success(access.RbacManager.List(public.GetUid(request)))
}

func (multi *Multi) MenuList(request *http.Request) core.Response {
	return core.Success(access.MenuManager.List(public.GetUid(request)))
}

func (multi *Multi) WebsiteList(request *http.Request) core.Response {
	return core.Success(access.MenuManager.List(public.GetUid(request)))
}
