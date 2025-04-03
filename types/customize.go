package types

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
)

var (
	customizeTransMap = map[string]string{
		"regexp": "regexp",
		"prefix": "^=",
		"suffix": "$=",
		"like":   "%=",
		"eq":     "=",
		"neq":    "!=",
		"in":     "in",
		"not_in": "not in",
		"gt":     ">",
		"egt":    ">=",
		"lt":     "<",
		"elt":    "<=",
	}
)

type Response struct {
	Type       string            `json:"type"`
	ResponseId int               `json:"response_id"`
	Status     int               `json:"status"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

type Action struct {
	Type      string       `json:"type"`
	Response  *Response    `json:"response"`
	Cc        *CustomizeCc `json:"cc"`
	BlockTime int          `json:"block_time"`
}

type CustomizeCc struct {
	Interval  int `json:"interval"`
	Threshold int `json:"threshold"`
}

type Option struct {
	Type        string `json:"type"`
	LeftFactor  string `json:"left_factor"`
	Operator    string `json:"operator"`
	RightFactor string `json:"right_factor"`
}

type Node struct {
	Type     string  `json:"type"`
	Logic    string  `json:"logic"`
	Option   *Option `json:"option"`
	Children []*Node `json:"children"`
}

type Entry struct {
	Id           int      `json:"id"`
	Name         string   `json:"name"`
	Servers      []string `json:"servers"`
	CreateTime   int64    `json:"create_time"`
	Priority     int      `json:"priority"`
	Status       int      `json:"status"`
	IsGlobal     int      `json:"is_global"`
	Src          int      `json:"src"`
	ExecutePhase string   `json:"execute_phase"`
	Action       *Action  `json:"action"`
	Root         *Node    `json:"root"`
}

func (e Entry) ToEntryFromDatabase() (*EntryFromDatabase, error) {
	actionBs, err := json.Marshal(e.Action)

	if err != nil {
		return nil, err
	}

	rootBs, err := json.Marshal(e.Root)

	if err != nil {
		return nil, err
	}

	executePhase := e.ExecutePhase

	if executePhase == "" {
		executePhase = "access"
	}

	return &EntryFromDatabase{
		Id:           e.Id,
		Name:         e.Name,
		Servers:      strings.Join(e.Servers, ","),
		CreateTime:   e.CreateTime,
		Priority:     e.Priority,
		Status:       e.Status,
		IsGlobal:     e.IsGlobal,
		Src:          e.Src,
		ExecutePhase: executePhase,
		Action:       string(actionBs),
		Root:         string(rootBs),
	}, nil
}

func (e Entry) ToExpression() string {
	lst := make([]string, 0)

	for _, node := range e.Root.Children {

		if strings.ToLower(node.Type) == "block" {
			exprs := make([]string, 0)

			for _, v := range node.Children {
				if v.Type == "block" {
					continue
				}

				expr, err := e.optionToExpr(v.Option)

				if err != nil {
					continue
				}

				exprs = append(exprs, expr)
			}

			exprsLength := len(exprs)

			if exprsLength > 0 {
				rawData := strings.Join(exprs, " and ")

				if exprsLength == 1 {
					lst = append(lst, rawData)
					continue
				}

				lst = append(lst, "("+rawData+")")
			}
		}

		if strings.ToLower(node.Type) == "option" {

			expr, err := e.optionToExpr(node.Option)

			if err != nil {
				continue
			}

			lst = append(lst, expr)
		}
	}

	return strings.Join(lst, " or ")
}

func (e Entry) optionToExpr(option *Option) (string, error) {
	left := strings.ToLower(option.Type)

	if option.LeftFactor != "" {
		left += "." + strings.ToLower(option.LeftFactor)
	}

	rawOpt := strings.ToLower(option.Operator)

	opt, ok := customizeTransMap[rawOpt]

	if !ok {
		return "", errors.New("无法将运算符【" + option.Operator + "】转换成表达式形式")
	}

	right := "'" + option.RightFactor + "'"

	if rawOpt == "in" || rawOpt == "not_in" {
		right = "{'" + strings.Join(strings.Split(option.RightFactor, ","), "','") + "'}"
	}

	return left + " " + opt + " " + right, nil
}

func (e Entry) Validate() error {
	if e.Root == nil {
		return errors.New("不能添加空规则")
	}

	if e.Root.Children == nil || len(e.Root.Children) == 0 {
		return errors.New("不能添加空规则")
	}

	var err error

	e.walk(e.Root, func(node *Node) bool {
		if node.Type == "option" {
			if node.Option.Type == "" || node.Option.Operator == "" {
				err = errors.New("不能添加空规则")
				return false
			}

			if node.Option.Type == "ip" {
				if node.Option.RightFactor == "" {
					err = errors.New("客户端IP不能为空")
					return false
				}

				if node.Option.Operator == "in" || node.Option.Operator == "not_in" {
					ips := strings.Split(node.Option.RightFactor, ",")
					for _, v := range ips {
						if ip := net.ParseIP(v); ip == nil {
							err = errors.New("客户端IP " + v + " 格式错误")
							return false
						}
					}
				} else {
					if ip := net.ParseIP(node.Option.RightFactor); ip == nil {
						err = errors.New("客户端IP " + node.Option.RightFactor + " 格式错误")
						return false
					}
				}
			}

			if node.Option.Type == "ip_range" {
				if node.Option.RightFactor == "" {
					err = errors.New("IP段不能为空")
					return false
				}

				if node.Option.Operator == "in" || node.Option.Operator == "not_in" {
					ips := strings.Split(node.Option.RightFactor, ",")
					for _, v := range ips {
						if _, _, errTmp := net.ParseCIDR(v); errTmp != nil {
							err = errors.New("IP段 " + v + " 格式错误，必须为CIDR表达式")
							return false
						}
					}
				} else {
					if _, _, errTmp := net.ParseCIDR(node.Option.RightFactor); errTmp != nil {
						err = errors.New("IP段 " + node.Option.RightFactor + " 格式错误，必须为CIDR表达式")
						return false
					}
				}
			}
		}

		return true
	})

	return err
}

func (e Entry) walk(node *Node, handler func(node *Node) bool) bool {
	if !handler(node) {
		return false
	}

	for _, v := range node.Children {
		if !e.walk(v, handler) {
			return false
		}
	}

	return true
}

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

func (efd EntryFromDatabase) ToEntry() (*Entry, error) {
	action := Action{}

	if err := json.Unmarshal([]byte(efd.Action), &action); err != nil {
		return nil, err
	}

	root := Node{}

	if err := json.Unmarshal([]byte(efd.Root), &root); err != nil {
		return nil, err
	}

	servers := make([]string, 0)

	if efd.Servers != "" {
		servers = strings.Split(efd.Servers, ",")
	}

	return &Entry{
		Id:           efd.Id,
		Name:         efd.Name,
		Servers:      servers,
		CreateTime:   efd.CreateTime,
		Priority:     efd.Priority,
		Status:       efd.Status,
		IsGlobal:     efd.IsGlobal,
		Src:          efd.Src,
		ExecutePhase: efd.ExecutePhase,
		Action:       &action,
		Root:         &root,
	}, nil
}

type WebsiteRuleLink struct {
	RuleId     int    `json:"rule_id"`
	ServerName string `json:"server_name"`
}
