package ptracer

import "golang.org/x/sys/unix"

type forkSyscall struct {
	regs unix.PtraceRegsAmd64
}

func (f *forkSyscall) newPid() uint64 {
	return f.regs.Rax
}
