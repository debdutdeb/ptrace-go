package ptracer

import (
	"context"
	"fmt"
	"log"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

type Tracer interface {
	Trace(ctx context.Context, syscalls ...uint64)
	Syscall() (Syscall, error)
}

type tracerState struct {
	forking bool
	ctx     context.Context
}

type remoteTracer struct {
	mut sync.Mutex

	pid int

	tracing map[uint64]bool

	// i don't like these many channels however,I'll let them slide for now
	cont chan struct{}

	// data channel cannot be shared across multiple tracers
	// that will block existing processes one too many times unnecessarily.
	// handle each tracing independently.
	data chan Syscall

	tracer chan Tracer

	err chan error

	tracerState
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

func Attach(pid int) (Tracer, error) {
	return attach(pid, false)
}

func AttachAndTrackSubprocesses(pid int) (Tracer, error) {
	return attach(pid, true)
}

func attach(pid int, trackForks bool) (Tracer, error) {
	r := remoteTracer{
		mut:         sync.Mutex{},
		pid:         pid,
		tracing:     make(map[uint64]bool),
		cont:        make(chan struct{}, 0),
		data:        make(chan Syscall, 1),
		err:         make(chan error, 1), // must be 1
		tracer:      make(chan Tracer, 1),
		tracerState: tracerState{},
	}

	r.mut.Lock()

	if trackForks {
		r.tracing[syscall.SYS_FORK] = true
	}

	err := unix.PtraceAttach(pid)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func (r *remoteTracer) Child() Tracer {
	return <-r.tracer
}

func (r *remoteTracer) Trace(ctx context.Context, syscalls ...uint64) {
	for _, code := range syscalls {
		r.tracing[uint64(code)] = true
	}

	r.tracerState.ctx = ctx

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

func (r *remoteTracer) iterate() {
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

	if r.tracerState.forking {
		r.tracerState.forking = false
		newPid := registers.Rax
		tracer, err := attach(int(newPid), true)
		if err != nil {
			r.handleError(err)
			return
		}

		tracer.Trace(r.tracerState.ctx, mapKeys(r.tracing)...)

		r.tracer <- tracer // send in a new tracer
	}

	if registers.Orig_rax == syscall.SYS_FORK {
		log.Println("fork detected")
		r.tracerState.forking = true
		return
	}

	r.parseSyscall(registers)
}

func (r *remoteTracer) handleError(err error) {
	r.err <- err
	r.data <- nil
	r.detach()
}

func (r *remoteTracer) detach() {
	r.err <- unix.PtraceDetach(r.pid)
}

func (r *remoteTracer) Syscall() (Syscall, error) {
	r.cont <- struct{}{} // PTRACE_CONTINUE
	return <-r.data, <-r.err
}

func mapKeys[K comparable, V any](m map[K]V) []K {
	var keys []K

	for k := range m {
		keys = append(keys, k)
	}

	return keys
}
