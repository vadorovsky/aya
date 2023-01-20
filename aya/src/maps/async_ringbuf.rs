//! A `Future` based [ring buffer map][ringbuf] that may be used to receive
//! events from eBPF programs. As of Linux 5.8, this is the preferred way to
//! transfer per-event data from eBPF programs to userspace.
//!
//! [ringbuf]: https://www.kernel.org/doc/html/latest/bpf/ringbuf.html

use std::os::{fd::AsRawFd, unix::prelude::RawFd};

#[cfg(feature = "async_std")]
use async_io::Async;
use bytes::BytesMut;
use thiserror::Error;
#[cfg(feature = "async_tokio")]
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard, AsyncFdReadyMutGuard};

use crate::maps::{
    ringbuf::{RingBuf, RingBufItem},
    MapData, MapError,
};

/// Async ring buffer error.
#[derive(Error, Debug)]
pub enum AsyncRingBufError {
    /// A map error.
    #[error("map error: {0}")]
    MapError(MapError),

    /// An IO error.
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

/// A `Future` based map that can be used to receive events from eBPF programs.
///
/// This is similar to [`AsyncPerfEventArray`], but different in a few ways:
/// * It's shared across all CPUs, which allows a strong ordering between events. It also makes the
///   buffer creation easier.
/// * Data notifications are delivered for every event instead of being sampled for every N event;
///   the eBPF program can also control notification delivery if sampling is desired for performance reasons.
/// * On the eBPF side, it supports the reverse-commit pattern where the event can be directly
///   written into the ring without copying from a temporary location.
/// * Dropped sample notifications goes to the eBPF program as the return value of `reserve`/`output`,
///   and not the userspace reader. This might require extra code to handle, but allows for more
///   flexible schemes to handle dropped samples.
///
/// To receive events you need to:
/// * call [`AsyncRingBuf::try_from`]
/// * poll the returned [`RingBuf`] to be notified when events are inserted in the buffer
/// * call [`RingBuf::next`] to read the events
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.8.
#[cfg(any(feature = "async_std", feature = "async_tokio"))]
pub struct AsyncRingBuf<T: AsRef<MapData>> {
    ring_buf: RingBuf<T>,

    #[cfg(feature = "async_std")]
    async_fd: Async<RawFd>,

    #[cfg(feature = "async_tokio")]
    async_fd: AsyncFd<RawFd>,
}

#[cfg(any(feature = "async_std", feature = "async_tokio"))]
impl<T: AsRef<MapData>> AsyncRingBuf<T> {
    pub(crate) fn new(map: T) -> Result<AsyncRingBuf<T>, MapError> {
        let ring_buf = RingBuf::new(map)?;
        #[cfg(any(feature = "async_std", feature = "async_tokio"))]
        let fd = ring_buf.as_raw_fd();
        Ok(AsyncRingBuf {
            ring_buf,
            #[cfg(feature = "async_std")]
            async_fd: Async::new(fd).unwrap(),
            #[cfg(feature = "async_tokio")]
            async_fd: AsyncFd::new(fd).unwrap(),
        })
    }
}

#[cfg(feature = "async_std")]
impl<T: AsRef<MapData>> AsyncRingBuf<T> {
    /// Try to take a new entry from the ringbuf.
    ///
    /// Returns `Some(item)` if the ringbuf is not empty.
    /// Returns `None` if the ringbuf is empty, in which case the caller may register for
    /// availability notifications through `epoll` or other APIs.
    // This is a streaming iterator which is not viable without GATs (stabilized in 1.65).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<RingBufItem<T>, AsyncRingBufError> {
        loop {
            let mut guard = self.async_fd.readable_mut().await?;
            match self.ring_buf.next() {
                Some(item) => return Ok(item),
                None => {
                    guard.clear_ready();
                    continue;
                }
            }
        }
    }
}

#[cfg(feature = "async_tokio")]
impl<T: AsRef<MapData>> AsyncRingBuf<T> {
    /// foo bar.
    pub async fn readable(&self) -> Result<AsyncFdReadyGuard<i32>, AsyncRingBufError> {
        self.async_fd.readable().await.map_err(|e| e.into())
    }

    /// foo bar.
    pub async fn readable_mut(&mut self) -> Result<AsyncFdReadyMutGuard<i32>, AsyncRingBufError> {
        self.async_fd.readable_mut().await.map_err(|e| e.into())
    }

    /// foo bar.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<RingBufItem<T>> {
        self.ring_buf.next()
    }

    // TODO(vadorovsky): Make this work without coping and without borrow
    // checker errors.
    //
    // Try to take a new entry from the ringbuf.
    // pub async fn read_item(
    //     &mut self,
    //     buffer: &mut BytesMut,
    // ) -> Result<RingBufItem<T>, AsyncRingBufError> {
    //     let mut ret: Option<RingBufItem<T>> = None;
    //     loop {
    //         let mut guard = self.async_fd.readable_mut().await?;
    //         match self.ring_buf.next() {
    //             Some(item) => {
    //                 ret = Some(item);
    //                 break;
    //             }
    //             None => {
    //                 guard.clear_ready();
    //                 continue;
    //             }
    //         }
    //     }

    //     return Ok(ret.unwrap());
    // }
}

#[cfg(feature = "async_std")]
impl<T: AsRef<MapData>> AsyncRingBuf<T> {
    /// Waits for the ring buffer map file descriptor to become readable.
    pub async fn readable(&self) -> Result<RingBufConsumer<T>, MapError> {
        self.async_fd.readable()
    }
}
