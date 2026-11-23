/*
Copyright © 2024 Keytos alan@keytos.io

Define MS-CHAPv2 packets
*/
package mschapv2

import "fmt"

type OpCode uint8

const (
	OpCodeChallenge OpCode = iota + 1
	OpCodeResponse
	OpCodeSuccess
	OpCodeFailure
)

func (o OpCode) String() string {
	switch o {
	case OpCodeChallenge:
		return "Challenge"
	case OpCodeResponse:
		return "Response"
	case OpCodeSuccess:
		return "Success"
	case OpCodeFailure:
		return "Failure"
	}
	return fmt.Sprintf("Unknown (%d)", uint8(o))
}
