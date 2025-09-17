// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

use alloc::{collections::VecDeque, vec::Vec};
use async_io::{AsyncRead, AsyncWrite};
use core::future::poll_fn;
use rust_std_stub::io::{self, Read, Write};

use crate::{Result, VirtioSerialError, SERIAL_DEVICE};

use log::info;
use async_trait::async_trait;
use spdmlib::{error::{SpdmResult, SPDM_STATUS_SEND_FAIL}};
extern crate alloc;
use alloc::sync::Arc;
use alloc::boxed::Box;
use spdmlib::common::SpdmDeviceIo;
use spin::Mutex;

const DEFAULT_TIMEOUT: u32 = 8000;

pub struct VirtioSerialPort {
    port_id: u32,
    cache: VecDeque<Vec<u8>>,
}

impl Write for VirtioSerialPort {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send_data(buf).map_err(|e| e.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for VirtioSerialPort {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf).map_err(|e| e.into())
    }
}

impl AsyncRead for VirtioSerialPort {
    async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        poll_fn(|_cx| match self.recv(buf) {
            Ok(size) => core::task::Poll::Ready(Ok(size)),
            Err(e) => match e {
                VirtioSerialError::NotReady => core::task::Poll::Pending,
                _ => core::task::Poll::Ready(Err(e.into())),
            },
        })
        .await
    }
}

impl AsyncWrite for VirtioSerialPort {
    async fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        poll_fn(|_cx| match self.send_data(buf) {
            Ok(size) => core::task::Poll::Ready(Ok(size)),
            Err(e) => match e {
                VirtioSerialError::NotReady => core::task::Poll::Pending,
                _ => core::task::Poll::Ready(Err(e.into())),
            },
        })
        .await
    }
}

#[async_trait]
impl SpdmDeviceIo for VirtioSerialPort {
    async fn send(&mut self, buffer: Arc<&[u8]>) -> SpdmResult {
        info!("vm call raw device send {:02x}: {:02x?}\n", buffer.len(), buffer.as_ref());
        let res: io::Result<usize> = poll_fn(|_cx| match self.send_data(buffer.as_ref()) {
            Ok(size) => core::task::Poll::Ready(Ok(size)),
            Err(e) => match e {
                VirtioSerialError::NotReady => core::task::Poll::Pending,
                _ => core::task::Poll::Ready(Err(e.into())),
            },
        })
        .await;
        res.map_err(|_| SPDM_STATUS_SEND_FAIL)?;
        Ok(())
    }

    async fn receive(
        &mut self,
        read_buffer: Arc<Mutex<&mut [u8]>>,
        _timeout: usize,
    ) -> core::result::Result<usize, usize> {
        let mut read_buffer = read_buffer.lock();
        let res: io::Result<usize> = poll_fn(|_cx| match self.recv(read_buffer.as_mut()) {
            Ok(size) => core::task::Poll::Ready(Ok(size)),
            Err(e) => match e {
                VirtioSerialError::NotReady => core::task::Poll::Pending,
                _ => core::task::Poll::Ready(Err(e.into())),
            },
        })
        .await;
        Ok(res.unwrap())
    }

    async fn flush_all(&mut self) -> SpdmResult {
        Ok(())
    }
}

impl VirtioSerialPort {
    pub fn new(port_id: u32) -> Self {
        Self {
            port_id,
            cache: VecDeque::new(),
        }
    }

    pub fn open(&self) -> Result<()> {
        SERIAL_DEVICE
            .lock()
            .get_mut()
            .ok_or(VirtioSerialError::InvalidParameter)?
            .allocate_port(self.port_id)
    }

    pub fn close(&self) -> Result<()> {
        SERIAL_DEVICE
            .lock()
            .get_mut()
            .ok_or(VirtioSerialError::InvalidParameter)?
            .free_port(self.port_id)
    }

    pub fn send_data(&self, data: &[u8]) -> Result<usize> {
        SERIAL_DEVICE
            .lock()
            .get_mut()
            .ok_or(VirtioSerialError::InvalidParameter)?
            .enqueue(data, self.port_id, DEFAULT_TIMEOUT)
    }

    pub fn recv(&mut self, data: &mut [u8]) -> Result<usize> {
        if self.cache.is_empty() {
            loop {
                let recv_bytes = SERIAL_DEVICE
                    .lock()
                    .get_mut()
                    .ok_or(VirtioSerialError::InvalidParameter)?
                    .dequeue(self.port_id, DEFAULT_TIMEOUT)?;
                self.cache.push_back(recv_bytes);

                if !SERIAL_DEVICE
                    .lock()
                    .get_mut()
                    .ok_or(VirtioSerialError::InvalidParameter)?
                    .can_recv(self.port_id)
                {
                    break;
                }
            }
        }

        let mut recvd = 0;
        while !self.cache.is_empty() {
            let front = self.cache.front_mut().unwrap();
            let expect = data.len() - recvd;
            if front.len() <= expect {
                data[recvd..recvd + front.len()].copy_from_slice(front);
                recvd += front.len();
                self.cache.pop_front();
            } else {
                data[recvd..].copy_from_slice(&front[..expect]);
                front.drain(..expect);
                recvd += expect;
            }
        }

        Ok(recvd)
    }
}

impl Drop for VirtioSerialPort {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
