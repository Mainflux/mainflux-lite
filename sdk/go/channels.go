package sdk

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/mainflux/mainflux/things"
)

const channelsEndpoint = "channels"

// CreateChannel - creates new channel and generates UUID
func CreateChannel(data, token string) (string, error) {
	url := fmt.Sprintf("%s/%s", serverAddr, channelsEndpoint)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(data))
	if err != nil {
		return "", err
	}

	resp, err := sendRequest(req, token, contentTypeJSON)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("%d", resp.StatusCode)
	}

	return resp.Header.Get("Location"), nil
}

// GetChannels - gets all channels
func GetChannels(token string) ([]things.Channel, error) {
	url := fmt.Sprintf("%s/%s?offset=%s&limit=%s",
		serverAddr, channelsEndpoint, strconv.Itoa(offset), strconv.Itoa(limit))
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := sendRequest(req, token, contentTypeJSON)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d", resp.StatusCode)
	}

	l := listChannelsRes{}
	err = json.Unmarshal(body, &l)
	if err != nil {
		return nil, err
	}
	return l.Channels, nil
}

// GetChannel - gets channel by ID
func GetChannel(id, token string) (things.Channel, error) {
	url := fmt.Sprintf("%s/%s/%s", serverAddr, channelsEndpoint, id)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return things.Channel{}, err
	}

	resp, err := sendRequest(req, token, contentTypeJSON)
	if err != nil {
		return things.Channel{}, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return things.Channel{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return things.Channel{}, fmt.Errorf("%d", resp.StatusCode)
	}

	c := things.Channel{}
	err = json.Unmarshal(body, &c)
	if err != nil {
		return things.Channel{}, err
	}
	return c, nil
}

// UpdateChannel - update a channel
func UpdateChannel(id, data, token string) error {
	url := fmt.Sprintf("%s/%s/%s", serverAddr, channelsEndpoint, id)
	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(data))
	if err != nil {
		return err
	}

	resp, err := sendRequest(req, token, contentTypeJSON)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%d", resp.StatusCode)
	}

	return nil
}

// DeleteChannel - removes channel
func DeleteChannel(id, token string) error {
	url := fmt.Sprintf("%s/%s/%s", serverAddr, channelsEndpoint, id)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	resp, err := sendRequest(req, token, contentTypeJSON)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("%d", resp.StatusCode)
	}

	return nil
}
