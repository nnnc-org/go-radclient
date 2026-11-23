/*
Copyright © 2024 Keytos alan@keytos.io

Define EAP Request/Response Types
*/
package eap

import "fmt"

type Type uint8

const (
	TypeIdentity     Type = 1
	TypeNotification Type = 2
	TypeNAK          Type = 3
	TypeMD5          Type = 4
	TypeTLS          Type = 13
	TypeTTLS         Type = 21
	TypePEAP         Type = 25
	TypeMsCHAPv2     Type = 26
	TypeExtensions   Type = 33
)

func (t Type) String() string {
	switch t {
	case TypeIdentity:
		return "Identity"
	case TypeNotification:
		return "Notification"
	case TypeNAK:
		return "Legacy-NAK"
	case TypeMD5:
		return "MD5-Challenge"
	case TypeTLS:
		return "TLS"
	case TypeTTLS:
		return "TTLS"
	case TypePEAP:
		return "PEAP"
	case TypeMsCHAPv2:
		return "MS-CHAPv2"
	case TypeExtensions:
		return "Extensions"
	}
	return fmt.Sprintf("Unknown (%d)", uint8(t))
}
