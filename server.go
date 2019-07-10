/*
	Copyright (c) 2019 @crosbymichael

	Permission is hereby granted, free of charge, to any person
	obtaining a copy of this software and associated documentation
	files (the "Software"), to deal in the Software without
	restriction, including without limitation the rights to use, copy,
	modify, merge, publish, distribute, sublicense, and/or sell copies
	of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be
	included in all copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
	EXPRESS OR IMPLIED,
	INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
	IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
	HOLDERS BE LIABLE FOR ANY CLAIM,
	DAMAGES OR OTHER LIABILITY,
	WHETHER IN AN ACTION OF CONTRACT,
	TORT OR OTHERWISE,
	ARISING FROM, OUT OF OR IN CONNECTION WITH
	THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	v1 "github.com/crosbymichael/guard/api/v1"
	"github.com/gogo/protobuf/types"
	"github.com/pkg/errors"
)

var empty = &types.Empty{}

const defaultWireguardDir = "/etc/wireguard"

func newServer(dir string) (*server, error) {
	if err := os.MkdirAll(defaultWireguardDir, 0700); err != nil {
		return nil, errors.Wrap(err, "create wireguard dir")
	}
	return &server{
		dir: dir,
	}, nil
}

type server struct {
	dir string
}

func (s *server) Create(ctx context.Context, r *v1.CreateRequest) (*v1.CreateResponse, error) {
	if r.ID == "" {
		return nil, errors.New("tunnel id cannot be empty")
	}
	if r.Address == "" {
		return nil, errors.New("address cannot be empty")
	}
	if r.ListenPort == 0 {
		return nil, errors.New("listen port cannot be 0")
	}
	path := filepath.Join(s.dir, r.ID)
	if err := os.Mkdir(path, 0700); err != nil {
		if os.IsExist(err) {
			return nil, errors.New("tunnel already exists")
		}
		return nil, errors.Wrap(err, "create tunnel directory")
	}
	key, err := newPrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	t := v1.Tunnel{
		ID:         r.ID,
		ListenPort: r.ListenPort,
		Address:    r.Address,
		PrivateKey: key,
	}

	dataPath := filepath.Join(path, "tunnel.json")
	if err := saveTunnel(dataPath, &t); err != nil {
		return nil, err
	}
	if err := s.saveConf(&t); err != nil {
		os.RemoveAll(path)

		return nil, err
	}
	if err := wgquick(ctx, "enable", t.ID); err != nil {
		return nil, errors.Wrap(err, "enable tunnel")
	}
	if err := wgquick(ctx, "start", t.ID); err != nil {
		return nil, errors.Wrap(err, "start tunnel")
	}
	return &v1.CreateResponse{
		Tunnel: &t,
	}, nil
}

func (s *server) Delete(ctx context.Context, r *v1.DeleteRequest) (*types.Empty, error) {
	if r.ID == "" {
		return nil, errors.New("tunnel id cannot be empty")
	}
	path := filepath.Join(s.dir, r.ID)
	if err := wgquick(ctx, "disable", r.ID); err != nil {
		return nil, errors.Wrap(err, "disable tunnel")
	}
	if err := wgquick(ctx, "stop", r.ID); err != nil {
		return nil, errors.Wrap(err, "stop tunnel")
	}
	if err := os.RemoveAll(path); err != nil {
		return nil, errors.Wrap(err, "remove data path")
	}
	if err := os.Remove(filepath.Join(s.dir, fmt.Sprintf("%s.conf", r.ID))); err != nil {
		return nil, errors.Wrap(err, "remove configuration")
	}
	return empty, nil
}

func (s *server) List(ctx context.Context, _ *types.Empty) (*v1.ListResponse, error) {
	return nil, nil
}

func (s *server) saveConf(t *v1.Tunnel) error {
	path := filepath.Join(s.dir, fmt.Sprintf("%s.conf", t.ID))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrapf(err, "create tunnel conf %s", path)
	}
	defer f.Close()
	if err := t.Render(f); err != nil {
		return errors.Wrap(err, "render tunnel to config")
	}
	return nil
}

func saveTunnel(path string, t *v1.Tunnel) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "create data.json")
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(t); err != nil {
		return errors.Wrap(err, "encode tunnel")
	}
	return nil
}

func newPrivateKey(ctx context.Context) (string, error) {
	data, err := wireguard(ctx, "genkey")
	if err != nil {
		return "", errors.Wrapf(err, "%s", data)
	}
	return string(data), nil
}

func wireguard(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "wg", args...)
	return cmd.CombinedOutput()
}

func wgquick(ctx context.Context, action, name string) error {
	cmd := exec.CommandContext(ctx, "systemctl", action, fmt.Sprintf("wg-quick@%s", name))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "%s", out)
	}
	return nil
}
