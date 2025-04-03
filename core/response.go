package core

import (
	"CloudWaf/core/common"
	"CloudWaf/core/language"
	"CloudWaf/public/validate"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type Response interface {
	WriteResponse(w http.ResponseWriter, statusCode int) error
}

type TextResponse struct {
	Content string
}

func (t *TextResponse) WriteResponse(w http.ResponseWriter, statusCode int) (err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(statusCode)
	_, err = w.Write([]byte(t.Content))
	return err
}

type HtmlResponse struct {
	Content string
}

func (h *HtmlResponse) WriteResponse(w http.ResponseWriter, statusCode int) (err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	_, err = w.Write([]byte(h.Content))
	return err
}

type JsonResponse struct {
	Code       int64       `json:"code"`
	Res        interface{} `json:"res"`
	Nonce      int64       `json:"nonce"`
	statusCode int
}

func (j *JsonResponse) SetCode(code int64) *JsonResponse {
	j.Code = code
	return j
}

func (j *JsonResponse) StatusCode() int {
	if j.statusCode == 0 {
		return http.StatusOK
	}

	return j.statusCode
}

func (j *JsonResponse) WriteResponse(w http.ResponseWriter, statusCode int) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	return json.NewEncoder(w).Encode(j)
}

type DownloadResponse struct {
	Filename       string
	FileSize       int64
	handler        func(d *DownloadResponse) error
	writer         http.ResponseWriter
	Offset         int64
	RemainBytes    int64
	SupportPartial bool
}

func (d *DownloadResponse) Write(bs []byte) (int, error) {
	return d.writer.Write(bs)
}

func (d *DownloadResponse) WriteResponse(w http.ResponseWriter, statusCode int) (err error) {
	if d.handler == nil {
		return errors.New("处理函数未设置")
	}
	w.Header().Set("Content-Description", "File Transfer")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment;filename=%s", url.QueryEscape(d.Filename)))
	w.Header().Set("Expires", "0")
	w.Header().Set("Cache-Control", "must-revalidate")
	w.Header().Set("Pragma", "Public")

	for i := 0; i < 1; i++ {
		if d.FileSize < 1 {
			break
		}
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", d.FileSize))

		if !d.SupportPartial {
			break
		}
		lw, ok := reflect.ValueOf(w).Interface().(*LoggingResponseWriter)
		if !ok {
			break
		}
		rRange := strings.TrimSpace(lw.Request.Header.Get("Range"))
		if !strings.HasPrefix(rRange, "bytes=") {
			break
		}
		rangeParts := strings.Split(strings.TrimPrefix(rRange, "bytes="), "-")
		start := 0
		end := int(d.FileSize - 1)
		if len(rangeParts) < 2 {
			break
		}

		rangeParts[0] = strings.TrimSpace(rangeParts[0])
		if rangeParts[0] != "" {
			start, _ = strconv.Atoi(rangeParts[0])
		}

		rangeParts[1] = strings.TrimSpace(rangeParts[1])
		if rangeParts[1] != "" {
			end, _ = strconv.Atoi(rangeParts[1])
		}

		d.Offset = int64(start)
		d.RemainBytes = int64(end - start)
		lw.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, d.FileSize))
		statusCode = http.StatusPartialContent
	}
	w.WriteHeader(statusCode)
	d.writer = w
	return d.handler(d)
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (g gzipResponseWriter) Write(bs []byte) (int, error) {
	return g.Writer.Write(bs)
}

type LoggingResponseWriter struct {
	writer      http.ResponseWriter
	Request     *http.Request
	StatusCode  int
	ResponseBuf *bytes.Buffer
	RequestBuf  *bytes.Buffer
	RequestTime int64
}

func NewLoggingResponseWriter(w http.ResponseWriter, r *http.Request) *LoggingResponseWriter {
	return &LoggingResponseWriter{
		writer:      w,
		Request:     r,
		StatusCode:  http.StatusOK,
		ResponseBuf: &bytes.Buffer{},
		RequestBuf:  &bytes.Buffer{},
		RequestTime: time.Now().UnixMilli(),
	}
}

func (w *LoggingResponseWriter) Write(bs []byte) (int, error) {
	w.ResponseBuf.Write(bs)
	return w.writer.Write(bs)
}

func (w *LoggingResponseWriter) Header() http.Header {
	return w.writer.Header()
}

func (w *LoggingResponseWriter) WriteHeader(statusCode int) {
	w.StatusCode = statusCode
	w.writer.WriteHeader(statusCode)
}

func DrainRequestBody(w *LoggingResponseWriter, r *http.Request) (err error) {
	if r.Body == nil || r.Body == http.NoBody {

		return nil
	}
	if _, err = w.RequestBuf.ReadFrom(r.Body); err != nil {
		return err
	}
	if err = r.Body.Close(); err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(w.RequestBuf.Bytes()))
	return nil
}

func CreateJsonResponse(code int64, res interface{}, statusCode int) *JsonResponse {
	switch v := res.(type) {
	case error:
		res = v.Error()
	case *JsonResponse:
		return v
	}

	return &JsonResponse{
		Code:       code,
		Res:        LocateRecursive(common.Copy(res)),
		Nonce:      time.Now().Unix(),
		statusCode: statusCode,
	}
}

func CreateDownloadResponse(filename string, fileSize int64, supportPartial bool, handler func(d *DownloadResponse) error) *DownloadResponse {
	return &DownloadResponse{
		Filename:       filename,
		FileSize:       fileSize,
		SupportPartial: supportPartial,
		Offset:         0,
		RemainBytes:    fileSize,
		handler:        handler,
	}
}

func Success(res interface{}) *JsonResponse {

	if v, ok := res.(string); ok && Language() == language.EN {
		if validate.HasDouble(v) {
			res = "Success"
		}
	}

	return CreateJsonResponse(CODE_SUCCESS, res, 200)
}

func Fail(res interface{}) *JsonResponse {
	if Language() == language.EN {
		switch v := res.(type) {
		case string:
			if validate.HasDouble(v) {
				res = "Fail"
			}
		case error:
			if validate.HasDouble(v.Error()) {
				res = "Fail"
			}
		}
	}

	return CreateJsonResponse(CODE_FAIL, res, 400)
}

func Text(content string) *TextResponse {
	return &TextResponse{
		Content: language.Locate(content),
	}
}

func Html(content string) *HtmlResponse {
	return &HtmlResponse{
		Content: language.Locate(content),
	}
}

func DownloadFile(filename, alias string) (response *DownloadResponse, err error) {
	if filename == "" {
		return response, errors.New("filename is empty")
	}
	if strings.Contains(filename, "../") || strings.Contains(filename, "..\\") {
		return response, errors.New("filename is invalid")
	}
	_, err = os.Stat(filename)

	if err != nil {
		return response, err
	}
	fp, err := os.Open(filename)

	if err != nil {
		return response, err
	}
	fi, err := fp.Stat()

	if err != nil {
		fp.Close()
		return response, err
	}
	if alias == "" {
		alias = filepath.Base(filename)
	}
	return CreateDownloadResponse(alias, fi.Size(), true, func(d *DownloadResponse) (err error) {
		defer fp.Close()
		if _, err = fp.Seek(d.Offset, 0); err != nil {
			return err
		}
		chunkSize := 1048576
		buf := make([]byte, chunkSize)

		for {
			n, err := fp.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			d.RemainBytes -= int64(n)
			if d.RemainBytes < 1 {
				_, err = d.Write(buf[:n+int(d.RemainBytes)])
				return err
			}
			_, err = d.Write(buf[:n])
			if err != nil {
				return err
			}
			if n < chunkSize {
				break
			}
		}

		return nil
	}), nil
}

func Download(filename string, data []byte) *DownloadResponse {
	return CreateDownloadResponse(filename, int64(len(data)), false, func(d *DownloadResponse) (err error) {
		_, err = d.Write(data)
		return err
	})
}
