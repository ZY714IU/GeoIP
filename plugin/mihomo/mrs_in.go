package mihomo

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ZY714IU/GeoIP/lib"
	"github.com/klauspost/compress/zstd"
	"go4.org/netipx"
)

var mrsMagicBytes = [4]byte{'M', 'R', 'S', 1} // MRSv1

const (
	TypeMRSIn = "mihomoMRS"
	DescMRSIn = "Convert mihomo MRS data to other formats"
)

func init() {
	lib.RegisterInputConfigCreator(TypeMRSIn, func(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
		return newMRSIn(action, data)
	})
	lib.RegisterInputConverter(TypeMRSIn, &MRSIn{
		Description: DescMRSIn,
	})
}

func newMRSIn(action lib.Action, data json.RawMessage) (lib.InputConverter, error) {
	var tmp struct {
		Name       string     `json:"name"`
		URI        string     `json:"uri"`
		InputDir   string     `json:"inputDir"`
		Want       []string   `json:"wantedList"`
		OnlyIPType lib.IPType `json:"onlyIPType"`
	}

	if len(data) > 0 {
		if err := json.Unmarshal(data, &tmp); err != nil {
			return nil, err
		}
	}

	if tmp.Name == "" && tmp.URI == "" && tmp.InputDir == "" {
		return nil, fmt.Errorf("❌ [type %s | action %s] missing inputDir or name or uri", TypeMRSIn, action)
	}

	if (tmp.Name != "" && tmp.URI == "") || (tmp.Name == "" && tmp.URI != "") {
		return nil, fmt.Errorf("❌ [type %s | action %s] name & uri must be specified together", TypeMRSIn, action)
	}

	// Filter want list
	wantList := make(map[string]bool)
	for _, want := range tmp.Want {
		if want = strings.ToUpper(strings.TrimSpace(want)); want != "" {
			wantList[want] = true
		}
	}

	return &MRSIn{
		Type:        TypeMRSIn,
		Action:      action,
		Description: DescMRSIn,
		Name:        tmp.Name,
		URI:         tmp.URI,
		InputDir:    tmp.InputDir,
		Want:        wantList,
	entry, found := entries[name]
	if !found {
		entry = lib.NewEntry(name)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	err = m.parseMRS(data, entry)
	if err != nil {
		return err
	}

	entries[name] = entry
	return nil
}

func (m *MRSIn) parseMRS(data []byte, entry *lib.Entry) error {
	reader, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer reader.Close()

	// header
	var header [4]byte
	_, err = io.ReadFull(reader, header[:])
	if err != nil {
		return err
	}
	if header != mrsMagicBytes {
		return fmt.Errorf("invalid MRS format")
	}

	// behavior
	var behavior [1]byte
	_, err = io.ReadFull(reader, behavior[:])
	if err != nil {
		return err
	}
	if behavior[0] != byte(1) { // RuleBehavior IPCIDR = 1
		return fmt.Errorf("invalid MRS IPCIDR data")
	}

	// count
	var count int64
	err = binary.Read(reader, binary.BigEndian, &count)
	if err != nil {
		return err
	}

	// extra (reserved for future using)
	var length int64
	err = binary.Read(reader, binary.BigEndian, &length)
	if err != nil {
		return err
	}
	if length < 0 {
		return fmt.Errorf("invalid MRS extra length")
	}
	if length > 0 {
		extra := make([]byte, length)
		_, err = io.ReadFull(reader, extra)
		if err != nil {
			return err
		}
	}

	//
	// rules
	//
	// version
	version := make([]byte, 1)
	_, err = io.ReadFull(reader, version)
	if err != nil {
		return err
	}
	if version[0] != 1 {
		return fmt.Errorf("invalid MRS rule version")
	}

	// rule length
	var ruleLength int64
	err = binary.Read(reader, binary.BigEndian, &ruleLength)
	if err != nil {
		return err
	}
	if ruleLength < 1 {
		return fmt.Errorf("invalid MRS rule length")
	}

	for i := int64(0); i < ruleLength; i++ {
		var a16 [16]byte
		err = binary.Read(reader, binary.BigEndian, &a16)
		if err != nil {
			return err
		}
		from := netip.AddrFrom16(a16).Unmap()

		err = binary.Read(reader, binary.BigEndian, &a16)
		if err != nil {
			return err
		}
		to := netip.AddrFrom16(a16).Unmap()

		iprange := netipx.IPRangeFrom(from, to)
		for _, prefix := range iprange.Prefixes() {
			if err := entry.AddPrefix(prefix); err != nil {
				return err
			}
		}
	}

	return nil
}
