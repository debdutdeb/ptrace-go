package ptracer

import (
	"syscall"

	"golang.org/x/sys/unix"
)

type WriteSyscall struct {
	pid  int
	regs unix.PtraceRegsAmd64
}

var _ Syscall = &WriteSyscall{}

func (w *WriteSyscall) Code() int {
	return syscall.SYS_WRITE
}

func (w *WriteSyscall) GetArgument(pos int) interface{} {
	return nil
}

func (w *WriteSyscall) FirstArgument() interface{} {
	return nil
}

func (w *WriteSyscall) SecondArgument() interface{} {
	return nil
}

func (w *WriteSyscall) ThirdArgument() interface{} {
	return nil
}

func (w *WriteSyscall) ContentLength() uint64 {
	return w.regs.Rdx
}

func (w *WriteSyscall) Content() (string, error) {
	data := make([]byte, w.ContentLength())

	_, err := unix.PtracePeekText(w.pid, uintptr(w.regs.Rsi), data)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
