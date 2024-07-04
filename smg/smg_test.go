package smg

import (
	"fmt"
	"net"
	"testing"
	"time"

	ov "github.com/cloudflare/cfrpki/ov"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type TestROA struct {
	ASN       uint32
	Prefix    *net.IPNet
	MaxLength int
}

func (r *TestROA) GetPrefix() *net.IPNet {
	return r.Prefix
}

func (r *TestROA) GetASN() uint32 {
	return r.ASN
}

func (r *TestROA) GetMaxLen() int {
	return r.MaxLength
}

type TestRoute struct {
	ASN    uint32
	Prefix *net.IPNet
}

func (r *TestRoute) GetPrefix() *net.IPNet {
	return r.Prefix
}

func (r *TestRoute) GetASN() uint32 {
	return r.ASN
}

func MakeRoAData() []ov.AbstractROA {
	_, ip1, _ := net.ParseCIDR("10.0.0.0/24") //65001
	_, ip2, _ := net.ParseCIDR("10.0.1.0/24") //65002
	_, ip3, _ := net.ParseCIDR("10.0.2.0/24") //65003
	_, ip4, _ := net.ParseCIDR("10.0.3.0/24") //65004
	_, ip5, _ := net.ParseCIDR("10.0.4.0/24") //65005

	vrp := []ov.AbstractROA{
		&TestROA{
			65001,
			ip1,
			24,
		},
		&TestROA{
			65002,
			ip2,
			24,
		},
		&TestROA{
			65003,
			ip3,
			25,
		},
		&TestROA{
			65004,
			ip4,
			25,
		},
		&TestROA{
			65005,
			ip5,
			26,
		},
	}
	return vrp
}

func MakeMOASData() ([]string, [][]uint32) {
	moas_route := []string{
		"10.0.0.0/24",
		"10.0.1.0/24",
		"10.0.2.0/24",
		"10.0.2.0/25",
		"10.0.3.0/24",
		"10.0.3.0/25",
		"10.0.4.0/24",
		"10.0.4.0/25",
		"10.0.4.0/26",
	}

	moas_asn := [][]uint32{
		{65001, 65011},                                                         //2 ASes
		{65002, 65012, 65022},                                                  //3 ASes
		{65003, 65013, 65023, 65033},                                           //4 ASes
		{65003, 65013, 65023, 65033, 65043},                                    //5 ASes
		{65004, 65014, 65024, 65034, 65044, 65054},                             //6 ASes
		{65004, 65014, 65024, 65034, 65044, 65054, 65064},                      //7 ASes
		{65005, 65015, 65025, 65035, 65045, 65055, 65065, 65075},               //8 ASes
		{65005, 65015, 65025, 65035, 65045, 65055, 65065, 65075, 65085},        //9 ASes
		{65005, 65015, 65025, 65035, 65045, 65055, 65065, 65075, 65085, 65095}, //10 ASes
	}
	return moas_route, moas_asn
}

func MakeKeyData(n int) MultSig {
	m := NewMultSig(n)
	return m
}

func TestSMG(t *testing.T) {
	vrp := MakeRoAData()
	moas_route, moas_asn := MakeMOASData()
	m := MakeKeyData(100)
	vrp_ov := ov.NewOV(vrp)

	for i, route := range moas_route {

		start_time := time.Now()

		var timer_object time.Duration
		var timer_sign time.Duration
		var timer_combine time.Duration
		var timer_validate time.Duration

		var repeats int64
		repeats = 0
		for ; repeats < 100; repeats++ {

			//create SMG object
			start_object_time := time.Now()
			smg_object := NewSMGObject(0, moas_asn[i], "0001", route)
			smg_hash := smg_object.HashObject()
			smg_G2, _ := bls.HashToG2(smg_hash, []byte{})
			elapsed_object_time := time.Since(start_object_time)
			timer_object += elapsed_object_time

			//sign
			start_sign_time := time.Now()
			sigmas := []bls.G2Jac{}
			signers := []int{}
			for asn := range smg_object.AsList {
				idx := int(asn) % 100
				sigmas = append(sigmas, m.psign(smg_hash, m.crs.parties[idx]))
				signers = append(signers, idx)
			}
			elapsed_sign_time := time.Since(start_sign_time)
			timer_sign += elapsed_sign_time

			//verify_combine
			start_combine_time := time.Now()
			msig := m.verifyCombine(smg_G2, signers, sigmas)
			elapsed_combine_time := time.Since(start_combine_time)
			timer_combine += elapsed_combine_time

			//validate
			start_validate_time := time.Now()
			//step 0: validate the format of SMG object
			if !smg_object.ValidateFormat() {
				t.Errorf("SMG object validation failed")
			}

			//step 1: verify the signature
			if !m.gverify(smg_G2, msig) {
				t.Errorf("SMG object signature validation failed")
			}

			//step 2: verify the SMG object against the VRP
			prefix := smg_object.GetPrefix()
			first_asn := smg_object.GetASList()[0]
			route := &TestRoute{
				first_asn,
				prefix,
			}
			_, rov, _ := vrp_ov.Validate(route)
			if rov != ov.STATE_VALID {
				t.Errorf("SMG object validation failed")
			}
			// if rov == ov.STATE_UNKNOWN {
			// 	fmt.Println("ROA not found")
			// } else if rov == ov.STATE_INVALID {
			// 	fmt.Println("ROA invalid")
			// } else if rov == ov.STATE_VALID {
			// 	fmt.Println("ROA valid")
			// }
			elapsed_validate_time := time.Since(start_validate_time)
			timer_validate += elapsed_validate_time
		}

		end_time := time.Now()
		elapsed_time := end_time.Sub(start_time).Abs().Milliseconds()
		fmt.Println("Time taken for SMG protocol: ", float64(elapsed_time)/float64((repeats+1)))
		fmt.Println("Time taken for SMG object creation: ", float64(timer_object.Milliseconds())/float64((repeats+1)))
		fmt.Println("Time taken for SMG object signing: ", float64(timer_sign.Milliseconds())/float64((repeats+1)))
		fmt.Println("Time taken for SMG object combine: ", float64(timer_combine.Milliseconds())/float64((repeats+1)))
		fmt.Println("Time taken for SMG object validation: ", float64(timer_validate.Milliseconds())/float64((repeats+1)))

	}

}
