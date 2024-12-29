package ptracer

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Syscall represents a syscall of a process at any time
type Syscall interface {
	Code() int

	GetArgument(position int) interface{}

	FirstArgument() interface{}
	SecondArgument() interface{}
	ThirdArgument() interface{}
}

type noopSyscall struct{}

var _ Syscall = &noopSyscall{}

func (w *noopSyscall) Code() int {
	return -1
}

func (w *noopSyscall) GetArgument(pos int) interface{} {
	return nil
}

func (w *noopSyscall) FirstArgument() interface{} {
	return nil
}

func (w *noopSyscall) SecondArgument() interface{} {
	return nil
}

func (w *noopSyscall) ThirdArgument() interface{} {
	return nil
}

func (r *remoteTracer) parseSyscall(registers unix.PtraceRegsAmd64) {
	if !r.shared.tracing[registers.Orig_rax] { // if not intentionally tracing then skip all unnecessary data transfers over channels
		r.iterate()
		return
	}

	switch registers.Orig_rax {
	case syscall.SYS_WRITE:
		r.dataChan <- &WriteSyscall{regs: registers, pid: r.pid}
	default: // shouldn't hit if tracing one of the supported ones
		r.dataChan <- &noopSyscall{}
	}
}
