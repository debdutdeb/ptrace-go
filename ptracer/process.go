package ptracer

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"
)

type ProcessController interface {
	Trace(ctx context.Context, syscalls ...int)
	Syscall() (Syscall, error)
}

type remoteTrace struct {
	pid int

	tracing map[uint64]bool

	cont chan struct{}

	data chan Syscall

	err chan error
}

/*
controller, err := ptrace.Attach(pid)
err.ifnotnil!

controller.Trace(syscall.SYS_WRITE, syscall.SYS_READ)

for call, err := controller.Syscall() {
	err.ifnotnil!

	write, ok := call.(ptrace.WriteSyscall)
	if ok {
		fmt.Print(write.Content())
	}
}
*/

func Attach(pid int) (ProcessController, error) {
	r := remoteTrace{
		pid:     pid,
		tracing: make(map[uint64]bool),
		cont:    make(chan struct{}, 0),
		data:    make(chan Syscall, 1),
		err:     make(chan error, 1), // must be 1
	}

	err := unix.PtraceAttach(pid)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func (r *remoteTrace) Trace(ctx context.Context, syscalls ...int) {
	for _, code := range syscalls {
		r.tracing[uint64(code)] = true
	}

	go func() {
		var wait unix.WaitStatus

		_, err := unix.Wait4(r.pid, &wait, 0, nil)
		if err != nil {
			r.handleError(err)
			return
		}

		for {
			select {
			case <-ctx.Done():
				r.detach()
				return
			case <-r.cont:
				r.iterate()
			}
		}
	}()
}

func (r *remoteTrace) iterate() {
	err := unix.PtraceSyscall(r.pid, 0)
	if err != nil {
		r.handleError(err)
		return
	}

	var wait unix.WaitStatus

	_, err = unix.Wait4(r.pid, &wait, 0, nil)
	if err != nil {
		r.handleError(err)
		return
	}

	if wait.Exited() {
		r.handleError(fmt.Errorf("process already exited"))
		return
	}

	var registers unix.PtraceRegsAmd64
	if err := unix.PtraceGetRegsAmd64(r.pid, &registers); err != nil {
		r.handleError(err)
		return
	}

	r.parseSyscall(registers)
}

func (r *remoteTrace) handleError(err error) {
	r.err <- err
	r.data <- nil
	r.detach()
}

func (r *remoteTrace) detach() {
	r.err <- unix.PtraceDetach(r.pid)
}

func (r *remoteTrace) Syscall() (Syscall, error) {
	r.cont <- struct{}{} // PTRACE_CONTINUE
	return <-r.data, <-r.err
}
