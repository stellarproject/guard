# guard

A GRPC server for managing wireguard tunnels.

## Status: alpha

## Requirements

Wireguard and it's untilities, `wg`, `wg-quick`, and `wg-quick@.service` must be installed on the system hosting
the `guard` server.

### Run the server

When you run the wireguard server it will automatically create its own wireguard tunnel
that the server binds to.  This makes the server secure to manage across your network.
Use the `--address` flag to manage this server.

```bash
> sudo guard server

INFO[0000] tunnel created                                tunnel=guard0
INFO[0000] created guard0 tunnel
{
 "id": "guard0",
 "listen_port": "10100",
 "address": "10.199.199.1/32",
 "public_key": "37uzie/EZzzDpRbVTUOtuVXwhht/599pdhseh9MJ7QE=",
 "endpoint": "127.0.0.1"
}
```

```bash
> sudo wg

interface: guard0
  public key: 37uzie/EZzzDpRbVTUOtuVXwhht/599pdhseh9MJ7QE=
  private key: (hidden)
  listening port: 10100
```

### Create a new tunnel


To create a new tunnel specify the address and the endpoint for the tunnel.
The last argument is used as the tunnel ID and interface name on the server.

```bash
> guard create --address 192.168.5.1/32 --endpoint 127.0.0.1:31000 wg0

{
 "id": "wg0",
 "listen_port": "31000",
 "address": "192.168.5.1/32",
 "public_key": "irDV3wkkNe6f1GLAPFNGjj0xsQsoxPCNko4Lf3igcjM=",
 "endpoint": "127.0.0.1"
}
```

### Delete a tunnel

Delete a tunnel using the tunnel ID

```bash
> guard delete wg0
```

### Create a new peer

To create a new peer and have all the keys generated for you use the `peers new` command.
The peer configuration will be output to `stdout` that you can copy and paste into your client.

```bash
> guard peers --tunnel wg0 new --ip 192.168.5.2/32 --dns 192.168.5.1 --ips 192.168.5.0/24 --ips 192.168.0.1/24 mypeer

[Interface]
PrivateKey = kFJ6VSq+l6sBPaI2DUbEWSVI83Kcfz/yo7WfVheT+FI=
Address = 192.168.5.2/32
DNS = 192.168.5.1

# wg0
[Peer]
PublicKey = irDV3wkkNe6f1GLAPFNGjj0xsQsoxPCNko4Lf3igcjM=
AllowedIPs = 192.168.5.0/24, 192.168.0.1/24
Endpoint = 127.0.0.1:31000
```

### List all tunnels

```bash
> guard list

[
 {
  "id": "wg0",
  "listen_port": "31000",
  "address": "192.168.5.1/32",
  "peers": [
   {
    "id": "mypeer",
    "public_key": "u/eGf6olYeFSH4XoPvOSZJb9swA/qWPAlfSxRBi6Uw8=",
    "allowed_ips": [
     "192.168.5.2/32"
    ],
   }
  ],
  "public_key": "irDV3wkkNe6f1GLAPFNGjj0xsQsoxPCNko4Lf3igcjM=",
  "endpoint": "127.0.0.1"
 }
]
```

### Delete a peer by ID

You can remove and update peers using the `peers` commands.

```bash
> guard peers --tunnel wg0 delete mypeer

{
 "id": "wg0",
 "listen_port": "31000",
 "address": "192.168.5.1/32",
 "public_key": "irDV3wkkNe6f1GLAPFNGjj0xsQsoxPCNko4Lf3igcjM=",
 "endpoint": "127.0.0.1"
}
```
