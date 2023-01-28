# pq-adapter-mullvad
Go utility for upgrading pre-quantum Mullvad peers to their post-quantum counterparts

## How it works
this tool uses Mullvad's experimental Post-Quantum key exchange [protocol](https://github.com/mullvad/mullvadvpn-app/blob/master/talpid-tunnel-config-client/proto/tunnel_config.proto) to generate the corresponding PQ-peer for the currently connected Pre-Q peer.

it uses [circl](https://github.com/cloudflare/circl)'s ([octeep](https://github.com/octeep)'s) implementation of Classic Mceliece.

## FAQ

### it doesn't work!
I know. It is currently a work in progress.
