package api

import (
	"context"
	"testing"
	"time"
)

func TestWaitWorkersJoinsOnCancel(t *testing.T) {
	s := &Server{}
	ctx, cancel := context.WithCancel(context.Background())

	started := make(chan struct{})
	s.goWorker(func() {
		close(started)
		<-ctx.Done() // exits when cancelled
	})
	<-started

	cancel()
	done := make(chan struct{})
	go func() { s.WaitWorkers(2 * time.Second); close(done) }()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("WaitWorkers did not return after workers exited")
	}
}

func TestWaitWorkersTimesOut(t *testing.T) {
	s := &Server{}
	block := make(chan struct{})
	s.goWorker(func() { <-block }) // never exits within the window

	start := time.Now()
	s.WaitWorkers(100 * time.Millisecond)
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("WaitWorkers returned too early: %v", elapsed)
	}
	close(block) // let the goroutine finish so the test is clean
}
