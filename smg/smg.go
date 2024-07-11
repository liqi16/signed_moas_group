package smg

import (
	sha256 "crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
)

type SMG_object struct {
	Version       int8
	AsList        []uint32
	AddressFamily string // '0001' for IPv4, '0002' for IPv6
	Prefix        string
}

func (smg *SMG_object) EncodeDER() ([]byte, error) {

	if !smg.ValidateFormat() {
		return nil, errors.New("SMG object format is invalid")
	}

	// Convert SMG object to ASN.1 DER format
	var asn1_obj struct {
		Version       int
		AsList        []int `asn1:"tag:0,sequence"` //asn1.BitString
		AddressFamily string
		Prefix        string
	}

	asn1_obj.Version = int(smg.Version)
	asn1_obj.AddressFamily = smg.AddressFamily
	asn1_obj.Prefix = smg.Prefix
	// Convert AS numbers to ASN.1 BitString
	// asn1_obj.AsList = asn1.BitString{Bytes: []byte{}, BitLength: 0}
	// for _, asn := range smg.AsList {
	// 	asn1_obj.AsList.Bytes = append(asn1_obj.AsList.Bytes, byte(asn))
	// 	asn1_obj.AsList.BitLength += 32
	// }
	asn1_obj.AsList = []int{}
	for _, asn := range smg.AsList {
		asn1_obj.AsList = append(asn1_obj.AsList, int(asn))
	}

	derBytes, err := asn1.Marshal(asn1_obj)
	if err != nil {
		return nil, err
	}

	// fmt.Printf("DER encoded data: %s\n", hex.EncodeToString(derBytes))

	return derBytes, nil
}

func DecodeDER(hexString string) SMG_object {
	// Decode the DER encoded data
	derBytes, err := hex.DecodeString(hexString)
	if err != nil {
		fmt.Println("Error decoding hex string")
	}

	var asn1_obj struct {
		Version       int
		AsList        []int `asn1:"tag:0,sequence"` //asn1.BitString
		AddressFamily string
		Prefix        string
	}

	_, err = asn1.Unmarshal(derBytes, &asn1_obj)
	if err != nil {
		fmt.Println("Error unmarshalling DER data")
	}

	// Convert ASN.1 DER format to SMG object
	smg_obj := SMG_object{
		Version:       int8(asn1_obj.Version),
		AsList:        []uint32{},
		AddressFamily: asn1_obj.AddressFamily,
		Prefix:        asn1_obj.Prefix,
	}
	for _, asn := range asn1_obj.AsList {
		smg_obj.AsList = append(smg_obj.AsList, uint32(asn))
	}

	//fmt.Printf("SMG object: %+v\n", smg_obj)
	return smg_obj
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
	// object_string := fmt.Sprintf("%d", smg.Version)
	// for _, asn := range smg.AsList {
	// 	object_string += fmt.Sprintf("%d", asn)
	// }
	// object_string += smg.AddressFamily
	// object_string += smg.Prefix
	hasher := sha256.New()
	// hasher.Write([]byte(object_string))
	object_bytes, _ := smg.EncodeDER()
	hasher.Write(object_bytes)
	return hasher.Sum(nil)
}

func (smg *SMG_object) GetPrefix() *net.IPNet {
	_, ipnet, _ := net.ParseCIDR(smg.Prefix)
	return ipnet
}

func (smg *SMG_object) GetASList() []uint32 {
	return smg.AsList
}
