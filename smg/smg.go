package smg

import (
	sha256 "crypto/sha256"
	"fmt"
	"net"
)

type SMG_object struct {
	Version       int8
	AsList        []uint32
	AddressFamily string // '0001' for IPv4, '0002' for IPv6
	Prefix        string
}

func NewSMGObject(version int8, as_list []uint32, address_family string, prefix string) *SMG_object {
	return &SMG_object{
		Version:       version,
		AsList:        as_list,
		AddressFamily: address_family,
		Prefix:        prefix,
	}
}

func (smg *SMG_object) ValidateFormat() bool {
	if smg.Version != 0 {
		fmt.Println("SMG Object Check Failed: Version is not 0.")
		return false
	}

	if len(smg.AsList) == 0 {
		fmt.Println("SMG Object Check Failed: AS List is empty.")
		return false
	}

	for _, asn := range smg.AsList {
		if asn > 4294967295 {
			fmt.Println("SMG Object Check Failed: AS number is greater than 4294967295.")
			return false
		}
	}

	if smg.AddressFamily != "0001" && smg.AddressFamily != "0002" {
		fmt.Println("SMG Object Check Failed: Address Family is not '0001'(IPv4) or '0002'(IPv6).")
		return false
	}

	_, _, err := net.ParseCIDR(smg.Prefix)
	if err != nil {
		fmt.Println("SMG Object Check Failed: Prefix is not a valid CIDR.")
		return false
	}

	return true
}

func (smg *SMG_object) HashObject() []byte {
	object_string := fmt.Sprintf("%d", smg.Version)
	for _, asn := range smg.AsList {
		object_string += fmt.Sprintf("%d", asn)
	}
	object_string += smg.AddressFamily
	object_string += smg.Prefix
	hasher := sha256.New()
	hasher.Write([]byte(object_string))
	return hasher.Sum(nil)
}

func (smg *SMG_object) GetPrefix() *net.IPNet {
	_, ipnet, _ := net.ParseCIDR(smg.Prefix)
	return ipnet
}

func (smg *SMG_object) GetASList() []uint32 {
	return smg.AsList
}
