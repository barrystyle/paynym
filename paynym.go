// Copyright (c) 2022 barrystyle
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

package main

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
)

func is_paynym_address(address string) bool {

	// ensure address passes base58check,
	// version is set to 0x47 (or 'P')
	// payload is 80 bytes total

	decoded, version, err := base58.CheckDecode(address)
	if err != nil {
		return false
	}

	if version != 0x47 {
		return false
	}

	if len(decoded) != 80 {
		return false
	}

	// decoded contains payload,
	// version is 0x01 or 0x02,
	// bitfield must be 0x00,
	// sign must be 0x02 or 0x03,
	// reserved must be unused

	payload_version := decoded[0]
	if payload_version < 0x01 || payload_version > 0x02 {
		return false
	}

	payload_bitfield := decoded[1]
	if payload_bitfield != 0x00 {
		return false
	}

	payload_sign := decoded[2]
	if payload_sign < 0x02 || payload_sign > 0x03 {
		return false
	}

	notify_pubkey := decoded[2:35]
	notify_addr, err := btcutil.NewAddressPubKey(notify_pubkey, &chaincfg.MainNetParams)
	if err != nil {
		return false
	}

	if !notify_addr.IsForNet(&chaincfg.MainNetParams) {
		return false
	}

	for b := 67; b < 79; b++ {
		if decoded[b] != 0x00 {
			return false
		}
	}

	return true
}

func main() {

	// paynym_test := "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA"
	paynym_test := "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97"

	if is_paynym_address(paynym_test) {
		fmt.Printf("valid\n")
	} else {
		fmt.Printf("invalid\n")
	}

}
