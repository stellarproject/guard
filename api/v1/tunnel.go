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

package v1

import (
	"io"
	"strings"
	"text/template"

	"github.com/pkg/errors"
)

const confFmt = `[Interface]
PrivateKey = {{.PrivateKey}}
{{if .ListenPort}}ListenPort = {{.ListenPort}}{{end}}
Address = {{.Address}}
{{if .DNS }}DNS = {{.DNS}}{{end}}
{{if .Masquerade}}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {{.Masquerade.Interface}} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {{.Masquerade.Interface}} -j MASQUERADE
{{end}}
{{range $peer := .Peers -}}
# {{$peer.ID}}
[Peer]
PublicKey = {{$peer.PublicKey}}
AllowedIPs = {{joinIPs $peer.AllowedIPs}}
{{if .Endpoint}}Endpoint = {{.Endpoint}}{{end}}
{{if .PersistentKeepalive}}PersistentKeepalive = {{.PersistentKeepalive}}{{end}}
{{end}}
`

func (t *Tunnel) Render(w io.Writer) error {
	tmp, err := template.New("wireguard").Funcs(template.FuncMap{
		"joinIPs": joinIPs,
	}).Parse(confFmt)
	if err != nil {
		return errors.Wrap(err, "parse template")
	}
	if err := tmp.Execute(w, t); err != nil {
		return errors.Wrap(err, "execute template")
	}
	return nil
}

func joinIPs(ips []string) string {
	return strings.Join(ips, ", ")
}
