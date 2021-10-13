// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/pkg/btf"
)

type funcMeta struct {
	SkbPos       int
	RetBTFTypeID uint32
	Addr         uint64
}

type Funcs struct {
	meta map[string]funcMeta
	addr map[uint64]string
}

func NewFuncs() (*Funcs, error) {
	m, err := getFuncsMeta()
	if err != nil {
		return nil, err
	}
	a, err := setAddrs(&m)
	if err != nil {
		return nil, err
	}

	f := &Funcs{
		meta: m,
		addr: a,
	}

	return f, nil
}

func (f *Funcs) GetNameByAddr(addr uint64) string {
	return f.addr[addr]
}

func (f *Funcs) Len() int {
	return len(f.meta)
}

func (f *Funcs) GetMeta() map[string]funcMeta {
	return f.meta
}

func setAddrs(meta *map[string]funcMeta) (map[uint64]string, error) {
	a2n := map[uint64]string{}

	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		name := line[2]
		if m, found := (*meta)[name]; found {
			addr, err := strconv.ParseUint(line[0], 16, 64)
			if err != nil {
				return nil, err
			}
			a2n[addr] = name
			m.Addr = addr
			(*meta)[name] = m

		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return a2n, nil
}

func getFuncsMeta() (map[string]funcMeta, error) {
	metas := map[string]funcMeta{}

	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, err
	}

	callback := func(typ btf.Type) {
		fn := typ.(*btf.Func)
		fnProto := fn.Type.(*btf.FuncProto)
		i := 1
		for _, p := range fnProto.Params {
			if ptr, ok := p.Type.(*btf.Pointer); ok {
				if strct, ok := ptr.Target.(*btf.Struct); ok {
					//if strct.Name == "sk_buff" && i <= 5 {
					if strct.Name == "sk_buff" && i == 1 {
						meta := funcMeta{
							SkbPos:       i,
							RetBTFTypeID: uint32(fnProto.Return.ID()),
						}
						metas[string(fn.Name)] = meta
						return
					}
				}
			}
			i += 1
		}
	}
	fn := &btf.Func{}
	spec.Iterate(callback, fn)

	return metas, nil
}
