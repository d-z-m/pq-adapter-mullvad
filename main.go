package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"golang.unexpl0.red/pq-adapter-mullvad/grpcapi"
	"time"

	"github.com/cloudflare/circl/kem/mceliece/mceliece460896f"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// bytes needed to store mceliece460896(f) ciphertext
const CRYPTO_CIPHERTEXTBYTES int = 188

// tuncfg server IP:port
const TUNCFG_ADDRESS = "10.64.0.1:1337"

// NIST level 3 version of mcEliece
const MCELIECE_VARIANT = "Classic-McEliece-460896f"

func main() {
	client, err := wgctrl.New()
	if err != nil {
		log.Fatal(err)
	}

	devices, err := client.Devices()
	if err != nil {
		fmt.Println("i ded")
		log.Fatal(err)
	}

	if len(devices) != 1 {
		log.Fatal(errors.New("Error: this tool expects only 1 wireguard device to be present...found " + fmt.Sprintf("%d", len(devices))))
	}
	pqUpgrade(TUNCFG_ADDRESS, devices[0].PublicKey)
}

func pqUpgrade(tuncfgAddress string, wgpubkey wgtypes.Key) {

	me := mceliece460896f.Scheme()

	fmt.Println(me.Name())
	//generate keypair
	mePubkey, mePrivkey, err := me.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	wgPskPrivkey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	wgPskPubkey := wgPskPrivkey.PublicKey()

	/*
	   type PskRequestExperimentalV1 struct {
	           state         protoimpl.MessageState
	           sizeCache     protoimpl.SizeCache
	           unknownFields protoimpl.UnknownFields

	           WgPubkey    []byte                     `protobuf:"bytes,1,opt,name=wg_pubkey,json=wgPubkey,proto3" json:"wg_pubkey,omitempty"`
	           WgPskPubkey []byte                     `protobuf:"bytes,2,opt,name=wg_psk_pubkey,json=wgPskPubkey,proto3" json:"wg_psk_pubkey,omitempty"`
	           KemPubkeys  []*KemPubkeyExperimentalV1 `protobuf:"bytes,3,rep,name=kem_pubkeys,json=kemPubkeys,proto3" json:"kem_pubkeys,omitempty"`
	   }

	   type KemPubkeyExperimentalV1 struct {
	           state         protoimpl.MessageState
	           sizeCache     protoimpl.SizeCache
	           unknownFields protoimpl.UnknownFields

	           AlgorithmName string `protobuf:"bytes,1,opt,name=algorithm_name,json=algorithmName,proto3" json:"algorithm_name,omitempty"`
	           KeyData       []byte `protobuf:"bytes,2,opt,name=key_data,json=keyData,proto3" json:"key_data,omitempty"`
	   }
	*/

	conn, err := grpc.Dial(TUNCFG_ADDRESS, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	qc := grpcapi.NewPostQuantumSecureClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	mePubkeyBytes, err := mePubkey.MarshalBinary()
	if err != nil {
		log.Fatal("Error marshaling mceliece public key to binary!")
	}

	pskResponse, err := qc.PskExchangeExperimentalV1(ctx, &grpcapi.PskRequestExperimentalV1{
		WgPubkey:    wgpubkey[:],
		WgPskPubkey: wgPskPubkey[:],
		KemPubkeys: []*grpcapi.KemPubkeyExperimentalV1{&grpcapi.KemPubkeyExperimentalV1{
			AlgorithmName: MCELIECE_VARIANT,
			KeyData:       mePubkeyBytes,
		}},
	})
	if err != nil {
		fmt.Println("i ded x2")
		log.Fatal(err)
	}
	fmt.Println("livin x2")

	if len(pskResponse.Ciphertexts) != 1 {
		log.Fatal("Error! expected 1 ciphertext. got " + fmt.Sprintf("%d", len(pskResponse.Ciphertexts)))
	}
	meCiphertext := pskResponse.Ciphertexts[0]

	if len(meCiphertext) != CRYPTO_CIPHERTEXTBYTES {
		log.Fatal("Error! expected ciphertext of length " + fmt.Sprintf("%d", CRYPTO_CIPHERTEXTBYTES) + "but got one of length " + fmt.Sprintf("%d", len(meCiphertext)))
	}

	ss, err := me.Decapsulate(mePrivkey, meCiphertext)

	if err != nil {
		fmt.Println("i ded x3")
		log.Fatal(err)
	}

	fmt.Println("New Private Key: " + base64.StdEncoding.EncodeToString(wgPskPrivkey[:]))
	fmt.Println("Assoc. Preshared key: " + base64.StdEncoding.EncodeToString(ss))

}

func xorAssign(dst, src []byte) {
	if len(src) > len(dst) {
		log.Fatal(errors.New("Error xoring key material!"))
	}
	for i, _ := range src {
		src[i] ^= dst[i]
	}
}

/* SPDX-License-Identifier: Apache-2.0
   Copyright 2019 Awn Umar <awn@spacetime.dev>
*/
// Wipes a byte slice with zeroes.
func wipeBytes(buf []byte) {
	if len(buf) == 0 {
		return
	}
	buf[0] = 0
	for bp := 1; bp < len(buf); bp *= 2 {
		copy(buf[bp:], buf[:bp])
	}
}
