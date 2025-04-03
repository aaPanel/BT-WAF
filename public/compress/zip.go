package compress

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func compressZip(zw *zip.Writer, path string, fi os.FileInfo, root string) error {
	header, err := zip.FileInfoHeader(fi)

	if err != nil {
		return err
	}

	header.Name = strings.TrimPrefix(strings.TrimPrefix(filepath.ToSlash(path), "./"), "/")
	header.Name = strings.TrimPrefix(strings.TrimPrefix(header.Name, root), "/")
	header.Method = zip.Deflate

	if header.Name == "" {
		return err
	}

	if fi.IsDir() {
		header.Name += "/"

		_, err := zw.CreateHeader(header)

		return err
	}

	w, err := zw.CreateHeader(header)

	if err != nil {
		return err
	}

	file, err := os.Open(path)

	if err != nil {
		return err
	}

	defer file.Close()

	_, err = io.Copy(w, file)

	return err
}

func Zip(dst string, srcList ...string) error {

	fp, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)

	if err != nil {
		return err
	}

	defer fp.Close()

	zw := zip.NewWriter(fp)

	defer zw.Close()

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

			return compressZip(zw, path, fi, root)
		})

		if err != nil {
			return err
		}
	}

	return nil
}

func Unzip(src, dst string) error {
	zr, err := zip.OpenReader(src)

	if err != nil {
		return err
	}

	defer zr.Close()

	for _, fz := range zr.File {
		filename := filepath.Join(dst, fz.Name)

		if fz.FileInfo().IsDir() {

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

			fzp, err := fz.Open()

			if err != nil {
				return err
			}

			defer fzp.Close()

			_, err = io.Copy(file, fzp)

			return err
		}()

		if err != nil {
			return err
		}
	}

	return nil
}
