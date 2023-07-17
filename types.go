package wupclientgo

type FSADirectoryEntry struct {
	Name   string
	IsFile bool
	Unk    []byte
}

type FSAStat struct {
	Flags uint32
	Mode  uint32
	Owner uint32
	Group uint32
	Size  uint32
}
