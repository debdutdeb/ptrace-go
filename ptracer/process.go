package ptracer

import (
	"context"
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Tracer interface {
	// TraceSyscalls registers which system calls to track
	TraceSyscalls(syscalls ...uint64)

	// Close stops tracing
	Close() error

	// Start starts the tracing process
	Start(ctx context.Context) error
	// Errors returns an error channel that should pass mostly TraceError struct implementing the error interface
	Errors() chan error

	// GetSyscalls returns a channel that passes current syscall getting run at any moment
	// Blocks further process until current syscall has been handled
	GetSyscalls()  Syscall
}

type tracerState struct {
	forking bool
	closed  bool
}

type TracerConfig struct {
	TraceForks         bool
	OnNewTracerCreated func(tracer Tracer) error
}

type tracerShared struct {
	ctx        context.Context
	tracing    map[uint64]bool
	errChan    chan error
	errorQueue []error // to avoid deadlock
	config     *TracerConfig
}

type remoteTracer struct {
	pid int

	continueChan chan struct{}

	// dataChan channel cannot be shared across multiple tracers
	// that will block existing processes one too many times unnecessarily.
	// handle each tracing independently.
	dataChan chan Syscall

	state tracerState

	shared *tracerShared
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

func Attach(pid int, config TracerConfig) (Tracer, error) {
	return attach(pid, config)
}

func attach(pid int, config TracerConfig) (Tracer, error) {
	r := remoteTracer{
		pid: pid,

		state: tracerState{},

		continueChan: make(chan struct{}, 0),
		dataChan:     make(chan Syscall, 1),

		shared: &tracerShared{
			errChan: make(chan error),
			tracing: make(map[uint64]bool),
			config:  &config,
		},
	}

	if config.TraceForks {
		r.shared.tracing[syscall.SYS_FORK] = true
	}

	err := unix.PtraceAttach(pid)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

/*
	go func() {
		for err := range tracer.Errors() {
			// handle all errors
		}
	}()
*/
func (r *remoteTracer) Errors() chan error {
	return r.shared.errChan
}

func (r *remoteTracer) TraceSyscalls(syscalls ...uint64) {
	for _, code := range syscalls {
		r.shared.tracing[uint64(code)] = true
	}
}

func (r *remoteTracer) consumeErrorQueue() {
	for len(r.shared.errorQueue) == 0 {
		time.Sleep(time.Second)
	}

	for _, err := range r.shared.errorQueue {
		r.shared.errChan <- err
	}

	r.consumeErrorQueue()
}

func (r *remoteTracer) newSubprocessAttach(pid int) (*remoteTracer, error) {
	nr := remoteTracer{
		pid: pid,

		state: tracerState{},

		continueChan: make(chan struct{}, 0),
		dataChan:     make(chan Syscall, 1),

		shared: r.shared,
	}

	err := unix.PtraceAttach(pid)
	if err != nil {
		return nil, err
	}

	return &nr, nil
}

func (r *remoteTracer) Start(ctx context.Context) error {
	r.shared.ctx = ctx

	var wait unix.WaitStatus

	_, err := unix.Wait4(r.pid, &wait, 0, nil)
	if err != nil {
		return err
	}

	go r.consumeErrorQueue()

	go func() {
		for {
			select {
			case <-ctx.Done():
				if err := r.Close(); err != nil {
					r.handleError(err)
				}

				return
			case <-r.continueChan:
				r.iterate()
			}
		}
	}()

	return nil
}

func (r *remoteTracer) Close() error {
	if r.state.closed {
		return TracerError{pid: r.pid, err: fmt.Errorf("tracer already detached")}
	}

	err := unix.PtraceDetach(r.pid)
	if err != nil {
		return err
	}

	r.state.closed = true

	return nil
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

	if r.state.forking {
		r.state.forking = false

		newPid := (&forkSyscall{registers}).newPid()
		tracer, err := r.newSubprocessAttach(int(newPid))
		if err != nil {
			tracer.handleError(err)
		} else {
			if r.shared.config == nil || r.shared.config.OnNewTracerCreated == nil {
				tracer.handleError(fmt.Errorf("no config found for new tracer, closing"))

				if err := tracer.Close(); err != nil {
					tracer.handleError(err)
				}
			} else {
				if err := r.shared.config.OnNewTracerCreated(tracer); err != nil {
					tracer.handleError(err)
				}
			}
		}
	}

	if r.isTracingForks() {
		r.state.forking = true
		return
	}

	r.parseSyscall(registers)
}

func (r *remoteTracer) isTracingForks() bool {
	return r.shared.tracing[syscall.SYS_FORK]
}

func (r *remoteTracer) handleError(err error) {
	r.shared.errorQueue = append(r.shared.errorQueue, TracerError{pid: r.pid, err: err})
}

func (r *remoteTracer) GetSyscalls() Syscall {
	r.continueChan <- struct{}{} // PTRACE_CONTINUE
	return <-r.dataChan
}

func mapKeys[K comparable, V any](m map[K]V) []K {
	var keys []K

	for k := range m {
		keys = append(keys, k)
	}

	return keys
}
