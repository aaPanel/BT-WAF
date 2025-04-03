package compress

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func compressTar(tw *tar.Writer, path string, fi os.FileInfo, root string) error {
	header, err := tar.FileInfoHeader(fi, "")

	if err != nil {
		return err
	}

	header.Name = strings.TrimPrefix(strings.TrimPrefix(filepath.ToSlash(path), "./"), "/")
	header.Name = strings.TrimPrefix(strings.TrimPrefix(header.Name, root), "/")

	if header.Name == "" {
		return err
	}

	if fi.IsDir() {
		header.Name += "/"

		err = tw.WriteHeader(header)

		return err
	}

	file, err := os.Open(path)

	if err != nil {
		return err
	}

	defer file.Close()

	err = tw.WriteHeader(header)

	if err != nil {
		return err
	}

	_, err = io.Copy(tw, file)

	return err
}

func Gzip(dst string, srcList ...string) error {

	fp, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)

	if err != nil {
		return err
	}

	defer fp.Close()

	zw := gzip.NewWriter(fp)

	defer zw.Close()

	tw := tar.NewWriter(zw)

	defer tw.Close()

	for _, src := range srcList {

		srcFi, err := os.Stat(src)

		if err != nil {
			return err
		}

		root := src

		if !srcFi.IsDir() {
			root = filepath.Dir(root)
		}

		root = strings.TrimPrefix(strings.TrimPrefix(filepath.ToSlash(root), "./"), "/")

		err = filepath.Walk(src, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			return compressTar(tw, path, fi, root)
		})

		if err != nil {
			return err
		}
	}

	return nil
}

func Ungzip(src, dst string) error {
	fp, err := os.Open(src)

	if err != nil {
		return err
	}

	defer fp.Close()

	zr, err := gzip.NewReader(fp)

	if err != nil {
		return err
	}

	defer zr.Close()

	return ungzip(zr, dst)
}

func UngzipContent(data []byte, dst string) error {
	zr, err := gzip.NewReader(bytes.NewBuffer(data))

	if err != nil {
		return err
	}

	defer zr.Close()

	return ungzip(zr, dst)
}

func ungzip(zr *gzip.Reader, dst string) error {
	tr := tar.NewReader(zr)

	for {
		header, err := tr.Next()

		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		filename := filepath.Join(dst, header.Name)

		if header.FileInfo().IsDir() {
			err = os.MkdirAll(filename, 0755)

			if err != nil {
				return err
			}

			continue
		}

		err = os.MkdirAll(filepath.Dir(filename), 0755)

		if err != nil {
			return err
		}

		file, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)

		if err != nil {
			return err
		}

		err = func() error {
			defer file.Close()

			_, err = io.Copy(file, tr)

			return err
		}()

		if err != nil {
			return err
		}
	}

	return nil
}

func Compress(data []byte) (bs []byte, err error) {
	buf := &bytes.Buffer{}

	func() {
		zw := gzip.NewWriter(buf)

		defer zw.Close()

		if _, err = zw.Write(data); err != nil {
			return
		}
	}()

	return buf.Bytes(), err
}

func Decompress(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewBuffer(data))

	if err != nil {
		return []byte{}, err
	}

	defer zr.Close()

	return io.ReadAll(zr)
}
