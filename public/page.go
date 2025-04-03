package public

import (
	"regexp"
	"strings"
)

type Page struct {
	PrevPage    string `json:"prev_page"`
	NextPage    string `json:"next_page"`
	StartPage   string `json:"start_page"`
	EndPage     string `json:"end_page"`
	CountStart  string `json:"count_start"`
	CountEnd    string `json:"count_end"`
	Fo          string `json:"fo"`
	Line        string `json:"line"`
	TotalPage   int    `json:"total_page"`
	TotalLine   int    `json:"total_line"`
	CurrentPage int    `json:"current_page"`
	PageSize    int    `json:"page_size"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	Uri         string `json:"uri"`
	LimitResult string `json:"limit_result"`
	CallBack    string `json:"call_back"`
	ListNum     int    `json:"list_num"`
}

func NewPage() *Page {
	p := &Page{}
	p.PrevPage = "上一页"
	p.NextPage = "下一页"
	p.StartPage = "首页"
	p.EndPage = "尾页"
	p.CountStart = "共"
	p.CountEnd = "条"
	p.Fo = "从"
	p.Line = "条"
	p.Uri = ""
	p.LimitResult = "1,2,3,4,5,6,7,8"
	p.ListNum = 4
	return p
}

func (p *Page) GetPage(pageNum int, pageSize int, totalLine int, uri, callBack string) string {
	p.CurrentPage = pageNum
	p.PageSize = pageSize
	p.TotalLine = totalLine
	p.TotalPage = totalLine / pageSize
	p.CallBack = callBack
	p.Uri = p.GetUri(uri)
	if totalLine%pageSize > 0 {
		p.TotalPage += 1
	}
	if p.CurrentPage > p.TotalPage {
		p.CurrentPage = p.TotalPage
	}
	if p.CurrentPage < 1 {
		p.CurrentPage = 1
	}
	p.StartLine = (p.CurrentPage - 1) * p.PageSize
	p.EndLine = p.CurrentPage * p.PageSize
	if p.EndLine > p.TotalLine {
		p.EndLine = p.TotalLine
	}
	pages := make(map[string]string)
	pages["1"] = p.GetStart()
	pages["2"] = p.GetPrev()
	pages["3"] = p.GetPages()
	pages["4"] = p.GetNext()
	pages["5"] = p.GetEnd()
	pages["6"] = "<span class='Pnumber'>" + IntToString(p.CurrentPage) + "/" + IntToString(p.TotalPage) + "</span>"
	pages["7"] = "<span class='Pline'>" + p.Fo + IntToString(p.StartLine) + "-" + IntToString(p.EndLine) + p.Line + "</span>"
	pages["8"] = "<span class='Pcount'>" + p.CountStart + IntToString(p.TotalLine) + p.CountEnd + "</span>"

	result := ""
	keys := strings.Split(p.LimitResult, ",")
	result += "<div>"
	for _, v := range keys {
		result += pages[v]
	}
	result += "</div>"
	return result

}

func (p *Page) GetEnd() string {
	endStr := ""
	if p.CurrentPage >= p.TotalPage {
		return endStr
	}
	pStr := IntToString(p.TotalPage)
	if p.CallBack != "" {
		endStr += "<a class='Pend' href='" + p.CallBack + "(" + pStr + ")'>" + p.EndPage + "</a>"
	} else {
		endStr += "<a class='Pend' href='" + p.Uri + "p=" + pStr + "'>" + p.EndPage + "</a>"
	}
	return endStr
}

func (p *Page) GetPages() string {
	pagesStr := ""
	num := 0
	cNum := p.CurrentPage - p.ListNum
	if cNum > p.ListNum {
		num = p.ListNum + cNum
	} else {
		num = p.ListNum
	}

	n := 0
	for i := 0; i < num; i++ {
		n = num - i
		page := p.CurrentPage - n
		if page > 0 {
			pStr := IntToString(page)
			if p.CallBack != "" {
				pagesStr += "<a class='Pnum' href='" + p.CallBack + "(" + pStr + ")'>" + pStr + "</a>"
			} else {
				pagesStr += "<a class='Pnum' href='" + p.Uri + "p=" + pStr + "'>" + pStr + "</a>"
			}
		}
	}
	if p.CurrentPage > 0 {
		pagesStr += "<span class='Pcurrent'>" + IntToString(p.CurrentPage) + "</span>"
	}
	if p.CurrentPage <= p.ListNum {
		num = p.ListNum + (p.ListNum - p.CurrentPage) + 1
	} else {
		num = p.ListNum
	}
	for i := 0; i < num; i++ {
		if i == 0 {
			continue
		}
		page := p.CurrentPage + i
		if page > p.TotalPage {
			break
		}
		pStr := IntToString(page)
		if p.CallBack != "" {
			pagesStr += "<a class='Pnum' href='" + p.CallBack + "(" + pStr + ")'>" + pStr + "</a>"
		} else {
			pagesStr += "<a class='Pnum' href='" + p.Uri + "p=" + pStr + "'>" + pStr + "</a>"
		}
	}
	return pagesStr

}

func (p *Page) GetNext() string {
	nextStr := ""
	if p.CurrentPage == p.TotalPage {
		return nextStr
	}

	nstr := IntToString(p.CurrentPage + 1)

	if p.CallBack != "" {
		nextStr += "<a class='Pnext' href='" + p.CallBack + "(" + nstr + ")'>" + p.NextPage + "</a>"
	} else {
		nextStr += "<a class='Pnext' href='" + p.Uri + "p=" + nstr + "'>" + p.NextPage + "</a>"
	}

	return nextStr
}

func (p *Page) GetStart() string {
	startStr := ""
	if p.CurrentPage == 1 {
		return startStr
	}

	if p.CallBack != "" {
		startStr += "<a class='Pstart' href='" + p.CallBack + "(1)'>" + p.StartPage + "</a>"
	} else {
		startStr += "<a class='Pstart' href='" + p.Uri + "p=1'>" + p.StartPage + "</a>"
	}

	return startStr
}

func (p *Page) GetPrev() string {
	prveStr := ""
	if p.CurrentPage == 1 {
		return prveStr
	}
	pstr := IntToString(p.CurrentPage - 1)
	if p.CallBack != "" {
		prveStr += "<a class='Pprev' href='" + p.CallBack + "(" + pstr + ")'>" + p.PrevPage + "</a>"
	} else {
		prveStr += "<a class='Pprev' href='" + p.Uri + "p=" + pstr + "'>" + p.PrevPage + "</a>"
	}

	return prveStr
}

func (p *Page) GetUri(uri string) string {
	re1 := regexp.MustCompile(`&p=\d+`)
	re2 := regexp.MustCompile(`\?p=\d+`)
	uri = re1.ReplaceAllString(uri, "&")
	uri = re2.ReplaceAllString(uri, "?")

	uriLen := len(uri)
	if strings.Contains(uri, "&") {
		if uri[uriLen-1:] != "&" {
			uri += "&"
		}
	} else {
		if !strings.Contains(uri, "?") {
			if uri[uriLen-1:] != "?" {
				uri += "?"
			}
		} else {
			if uri[uriLen-1:] != "&" {
				uri += "&"
			}
		}
	}
	return uri
}
