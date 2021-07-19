package utils

import (
	"bytes"
	"errors"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
)

func SendWantedFileToServer(uri string, params map[string]string, paramName, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}

	fileContents, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}

	fi, err := file.Stat()
	if err != nil {
		return err
	}
	file.Close()

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(paramName, fi.Name())
	if err != nil {
		return err
	}

	part.Write(fileContents)
	for key, val := range params {
		_ = writer.WriteField(key, val)
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", uri, body)
	if err != nil {
		return err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}

	if resp.StatusCode != http.StatusNoContent {
		return errors.New("request didn't go through successfully")
	}

	return nil
}
