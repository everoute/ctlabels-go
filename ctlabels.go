/*
Conntrack Label
see https://docs.google.com/spreadsheets/d/1jADYgo0tt1-Q9GYglZkRoiDRn0VGHyj2zNVNDPxgxLU/edit?usp=sharing

Traffic Visualization

| 127-126 | 125-124         | 123-108 | 107-92  | 91-88     | 87-32 | 31-4      | 3-0 |
| not     | encoding scheme | reply   | origin  | bridge id | not   | bridge id | not |
| set     | (0x01)          | in_port | in_port | high bits | set   | low bits  | set |

Micro Segmentation

| 127         | 126            | 125-124         | 123-108 | 107-92  | 91-90   | 89-88   | 87-60      | 59-32        | 31-4 |  3-0   |
| work policy | monitor policy | encoding scheme | reply   | origin  | reply   | origin  | work mode  | monitor mode |      | round  |
| action drop | action drop    | (0x11)          | in_port | in_port | source  | source  | flow id    | flow id      |      | number |

*/

package ctlabels

import (
	"encoding/hex"
	"fmt"
	"strings"

	numeric "github.com/everoute/numeric-go"
)

type EncodingScheme uint8

const (
	EncodingSchemeOld                  EncodingScheme = 0b00
	EncodingSchemeTrafficVisualization EncodingScheme = 0b01
	EncodingSchemeReserved             EncodingScheme = 0b10
	EncodingSchemeMicroSegmentation    EncodingScheme = 0b11
)

// PacketSource is the source bridge of the packet
// Used 2 bits only
// 0b10: Local Bridge
// 0b11: Uplink Bridge
type PacketSource uint8

const (
	PacketSourceLocalBridge  PacketSource = 0b10
	PacketSourceUplinkBridge PacketSource = 0b11
)

type DecodedTrafficVisualizationConntrackLabels struct {
	// RoundNumber uint8 // 4 bits
	BridgeID uint32 `json:"bridge_id"`
	// MonitorPolicySequence   uint32 // 28 bits
	// MonitorPolicyID         uint32 // Equals to MonitorPolicySequence | RoundNumber << 28
	// WorkPolicySequence      uint32 // 28 bits
	// WorkPolicyID            uint32 // Equals to WorkPolicySequence | RoundNumber << 28
	OriginInport   uint16         `json:"origin_inport"`
	ReplyInport    uint16         `json:"reply_inport"`
	EncodingScheme EncodingScheme `json:"encoding_scheme"`
	// MonitorPolicyActionDrop bool
	// WorkPolicyActionDrop    bool
}

type DecodedMicroSegmentationConntrackLabels struct {
	RoundNumber             uint8          `json:"round_number"`          // 4 bits
	MonitorFlowSequence     uint32         `json:"monitor_flow_sequence"` // 28 bits
	MonitorFlowID           uint32         `json:"monitor_flow_id"`       // Equals to MonitorFlowSequence | RoundNumber << 28
	WorkFlowSequence        uint32         `json:"work_flow_sequence"`    // 28 bits
	WorkFlowID              uint32         `json:"work_flow_id"`          // Equals to WorkFlowSequence | RoundNumber << 28
	OriginPacketSource      PacketSource   `json:"origin_packet_source"`  // 2 bits
	ReplyPacketSource       PacketSource   `json:"reply_packet_source"`   // 2 bits
	OriginInport            uint16         `json:"origin_inport"`
	ReplyInport             uint16         `json:"reply_inport"`
	EncodingScheme          EncodingScheme `json:"encoding_scheme"`
	MonitorPolicyActionDrop bool           `json:"monitor_policy_action_drop"`
	WorkPolicyActionDrop    bool           `json:"work_policy_action_drop"`
}

// Mask for the conntrack labels
var (
	// Encoding Scheme
	EncodingSchemeShift  = uint8(124)
	EncodingSchemeLength = uint8(2)
	EncodingSchemeMask   = numeric.Mask(EncodingSchemeLength).ShiftLeft(EncodingSchemeShift)

	// Common bits
	ReplyInportShift   = uint8(108)
	ReplyInportLength  = uint8(16)
	ReplyInportMask    = numeric.Mask(ReplyInportLength).ShiftLeft(ReplyInportShift)
	OriginInportShift  = uint8(92)
	OriginInportLength = uint8(16)
	OriginInportMask   = numeric.Mask(OriginInportLength).ShiftLeft(OriginInportShift)
	RoundNumberShift   = uint8(0)
	RoundNumberLength  = uint8(4)
	RoundNumberMask    = numeric.Mask(RoundNumberLength).ShiftLeft(RoundNumberShift)

	// Traffic Visualization
	// Encoding Scheme here 125-124
	// ReplyInportMask  here 123-108
	// OriginInportMask here 107-92
	BridgeIDHighBitsShift  = uint8(88)
	BridgeIDHighBitsLength = uint8(4)
	BridgeIDHighBitsMask   = numeric.Mask(BridgeIDHighBitsLength).ShiftLeft(BridgeIDHighBitsShift)
	BridgeIDLowBitsShift   = uint8(4)
	BridgeIDLowBitsLength  = uint8(28)
	BridgeIDLowBitsMask    = numeric.Mask(BridgeIDLowBitsLength).ShiftLeft(BridgeIDLowBitsShift)

	// Micro Segmentation
	WorkPolicyActionDropShift    = uint8(127)
	WorkPolicyActionDropMask     = numeric.Mask(1).ShiftLeft(WorkPolicyActionDropShift)
	MonitorPolicyActionDropShift = uint8(126)
	MonitorPolicyActionDropMask  = numeric.Mask(1).ShiftLeft(MonitorPolicyActionDropShift)
	// Encoding Scheme here 125-124
	// ReplyInportMask  here 123-108
	// OriginInportMask here 107-92
	ReplyPacketSourceLength     = uint8(2)
	ReplyPacketSourceShift      = uint8(90)
	ReplyPacketSourceMask       = numeric.Mask(ReplyPacketSourceLength).ShiftLeft(ReplyPacketSourceShift)
	OriginPacketSourceLength    = uint8(2)
	OriginPacketSourceShift     = uint8(88)
	OriginPacketSourceMask      = numeric.Mask(OriginPacketSourceLength).ShiftLeft(OriginPacketSourceShift)
	WorkPolicySequenceLength    = uint8(28)
	WorkPolicySequenceShift     = uint8(60)
	WorkPolicySequenceMask      = numeric.Mask(WorkPolicySequenceLength).ShiftLeft(WorkPolicySequenceShift)
	MonitorPolicySequenceLength = uint8(28)
	MonitorPolicySequenceShift  = uint8(32)
	MonitorPolicySequenceMask   = numeric.Mask(MonitorPolicySequenceLength).ShiftLeft(MonitorPolicySequenceShift)
	// round number here 3-0
)

// DecodeConntrackLabels decodes the conntrack labels.
// Labels is a 16 bytes array, and it's little endian.
func DecodeConntrackLabels(labels []byte) (EncodingScheme, any, error) {
	// assert len(labels) == 16
	if len(labels) != 16 {
		return 0, nil, fmt.Errorf("invalid labels length: %d want 16", len(labels))
	}
	scheme, err := DecodeScheme(numeric.Uint128FromLittleEndianBytes(labels))
	if err != nil {
		return 0, nil, err
	}
	switch scheme {
	case EncodingSchemeOld:
		fallthrough
	case EncodingSchemeReserved:
		return scheme, nil, nil
	case EncodingSchemeTrafficVisualization:
		decoded, err := DecodeTrafficVisualization(numeric.Uint128FromLittleEndianBytes(labels))
		if err != nil {
			return 0, nil, err
		}
		return scheme, decoded, nil
	case EncodingSchemeMicroSegmentation:
		decoded, err := DecodeMicroSegmentation(numeric.Uint128FromLittleEndianBytes(labels))
		if err != nil {
			return 0, nil, err
		}
		return scheme, decoded, nil
	}
	return 0, nil, fmt.Errorf("invalid scheme: %d", scheme)
}

func DecodeScheme(labels numeric.Uint128) (EncodingScheme, error) {
	scheme := labels.And(EncodingSchemeMask).ShiftRight(EncodingSchemeShift)
	switch EncodingScheme(scheme.Low) {
	case EncodingSchemeTrafficVisualization:
		return EncodingSchemeTrafficVisualization, nil
	case EncodingSchemeMicroSegmentation:
		return EncodingSchemeMicroSegmentation, nil
	case EncodingSchemeReserved:
		return EncodingSchemeReserved, nil
	case EncodingSchemeOld:
		return EncodingSchemeOld, nil
	}
	return 0, fmt.Errorf("invalid scheme: %d", scheme)
}

func DecodeTrafficVisualization(labels numeric.Uint128) (DecodedTrafficVisualizationConntrackLabels, error) {
	decoded := DecodedTrafficVisualizationConntrackLabels{}

	bridgeIDHigh := labels.And(BridgeIDHighBitsMask).ShiftRight(BridgeIDHighBitsShift)
	bridgeIDLow := labels.And(BridgeIDLowBitsMask).ShiftRight(BridgeIDLowBitsShift)
	decoded.BridgeID = uint32(bridgeIDHigh.Low)<<BridgeIDLowBitsLength | uint32(bridgeIDLow.Low)

	decoded.OriginInport = uint16(labels.And(OriginInportMask).ShiftRight(OriginInportShift).Low)
	decoded.ReplyInport = uint16(labels.And(ReplyInportMask).ShiftRight(ReplyInportShift).Low)
	decoded.EncodingScheme = EncodingScheme(labels.And(EncodingSchemeMask).ShiftRight(EncodingSchemeShift).Low)

	return decoded, nil
}

func DecodeMicroSegmentation(labels numeric.Uint128) (DecodedMicroSegmentationConntrackLabels, error) {
	decoded := DecodedMicroSegmentationConntrackLabels{}

	decoded.RoundNumber = uint8(labels.And(RoundNumberMask).ShiftRight(RoundNumberShift).Low)
	decoded.MonitorFlowSequence = uint32(labels.And(MonitorPolicySequenceMask).ShiftRight(MonitorPolicySequenceShift).Low)
	if decoded.MonitorFlowSequence != 0 {
		decoded.MonitorFlowID = decoded.MonitorFlowSequence | (uint32(decoded.RoundNumber) << MonitorPolicySequenceLength)
	}
	decoded.WorkFlowSequence = uint32(labels.And(WorkPolicySequenceMask).ShiftRight(WorkPolicySequenceShift).Low)
	if decoded.WorkFlowSequence != 0 {
		decoded.WorkFlowID = decoded.WorkFlowSequence | (uint32(decoded.RoundNumber) << WorkPolicySequenceLength)
	}
	decoded.OriginPacketSource = PacketSource(labels.And(OriginPacketSourceMask).ShiftRight(OriginPacketSourceShift).Low)
	decoded.ReplyPacketSource = PacketSource(labels.And(ReplyPacketSourceMask).ShiftRight(ReplyPacketSourceShift).Low)
	decoded.OriginInport = uint16(labels.And(OriginInportMask).ShiftRight(OriginInportShift).Low)
	decoded.ReplyInport = uint16(labels.And(ReplyInportMask).ShiftRight(ReplyInportShift).Low)
	decoded.EncodingScheme = EncodingScheme(labels.And(EncodingSchemeMask).ShiftRight(EncodingSchemeShift).Low)
	decoded.MonitorPolicyActionDrop = labels.And(MonitorPolicyActionDropMask).ShiftRight(MonitorPolicyActionDropShift).Low != 0
	decoded.WorkPolicyActionDrop = labels.And(WorkPolicyActionDropMask).ShiftRight(WorkPolicyActionDropShift).Low != 0

	return decoded, nil
}

func removeHexPrefix(str string) string {
	if strings.HasPrefix(str, "0x") {
		return str[2:]
	}
	return str
}

func CTLabelsStrToBigEndianBytes(str string) []byte {
	str = removeHexPrefix(str)
	if len(str) < 32 { // want 128 bits
		// prepend 0 to the string
		str = strings.Repeat("0", 32-len(str)) + str
	}
	bigEndianLabels, err := hex.DecodeString(str)
	if err != nil {
		return nil
	}
	return bigEndianLabels
}

func CTLabelsStrToLittleEndianBytes(str string) []byte {
	return numeric.SwapBytes(CTLabelsStrToBigEndianBytes(str))
}

func CTLabelsStringToBinaryString(str string) string {
	bigEndianLabels := CTLabelsStrToBigEndianBytes(str)
	if bigEndianLabels == nil {
		return ""
	}
	return numeric.FormatBigEndianBinaryString(bigEndianLabels, "")
}
