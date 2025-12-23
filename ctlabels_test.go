package ctlabels_test

import (
	"encoding/json"
	"fmt"
	"testing"

	ctlabels "github.com/everoute/ctlabels-go"
	numeric "github.com/everoute/numeric-go"
	. "github.com/onsi/gomega"
)

func TestDecodeMicroSegmentation(t *testing.T) {
	RegisterTestingT(t)
	labelsStr := "0x70001000ae80002a780010e10000000b"
	labels := ctlabels.CTLabelsStrToLittleEndianBytes(labelsStr)
	Expect(labels).ShouldNot(BeNil())

	decoded, err := ctlabels.DecodeMicroSegmentation(numeric.Uint128FromLittleEndianBytes(labels))
	Expect(err).Should(BeNil())
	jsonStr, err := json.Marshal(decoded)
	Expect(err).Should(BeNil())
	expected := ctlabels.DecodedMicroSegmentationConntrackLabels{
		RoundNumber:             0b1011,
		MonitorFlowSequence:     0b1000000000000001000011100001,
		MonitorFlowID:           0b1011_1000000000000001000011100001,
		WorkFlowSequence:        0b1000000000000000001010100111,
		WorkFlowID:              0b1011_1000000000000000001010100111,
		OriginPacketSource:      ctlabels.PacketSource(0b10),
		ReplyPacketSource:       ctlabels.PacketSource(0b11),
		OriginInport:            0b0000000000001010,
		ReplyInport:             0b0000000000000001,
		EncodingScheme:          ctlabels.EncodingScheme(0b11),
		MonitorPolicyActionDrop: true,
		WorkPolicyActionDrop:    false,
	}
	expectJson, err := json.Marshal(expected)
	Expect(err).Should(Succeed())
	Expect(jsonStr).Should(Equal(expectJson))
}

func TestDecodeTrafficVisualization(t *testing.T) {
	RegisterTestingT(t)
	labelsStr := "0x10011000240000000000000056789ab0"
	labels := ctlabels.CTLabelsStrToLittleEndianBytes(labelsStr)
	Expect(labels).ShouldNot(BeNil())
	decoded, err := ctlabels.DecodeTrafficVisualization(numeric.Uint128FromLittleEndianBytes(labels))
	Expect(err).Should(BeNil())
	jsonStr, err := json.Marshal(decoded)
	Expect(err).Should(BeNil())
	fmt.Println(ctlabels.CTLabelsStringToBinaryString(labelsStr))
	expected := ctlabels.DecodedTrafficVisualizationConntrackLabels{
		BridgeID:       0b0100_0101_0110_0111_1000_1001_1010_1011, // 0x456789ab
		OriginInport:   0b0000_0000_0000_0010,
		ReplyInport:    0b0000_0000_0001_0001,
		EncodingScheme: ctlabels.EncodingScheme(0b01),
	}
	expectJson, err := json.Marshal(expected)
	Expect(err).Should(Succeed())
	Expect(jsonStr).Should(Equal(expectJson))
}
