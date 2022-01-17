use std::io::{self, BufRead, Read, Write};

pub struct PipeReader {
    receiver: crossbeam_channel::Receiver<Vec<u8>>,
    buffer: Vec<u8>,
    position: usize,
}

pub struct PipeWriter {
    sender: crossbeam_channel::Sender<Vec<u8>>,
    buffer: Vec<u8>,
    size: usize,
}

pub fn buffered_pipe(write_buf_sz: usize) -> (PipeReader, PipeWriter) {
    let (tx, rx) = crossbeam_channel::bounded(0);
    let write_buf_sz = write_buf_sz.max(1);
    (
        PipeReader {
            receiver: rx,
            buffer: Vec::new(),
            position: 0,
        },
        PipeWriter {
            sender: tx,
            buffer: Vec::with_capacity(write_buf_sz),
            size: write_buf_sz,
        },
    )
}

fn epipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed")
}

impl BufRead for PipeReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.position >= self.buffer.len() {
            if let Ok(data) = self.receiver.recv() {
                debug_assert!(!data.is_empty());
                self.buffer = data;
                self.position = 0;
            }
        }
        Ok(&self.buffer[self.position..])
    }

    fn consume(&mut self, amt: usize) {
        debug_assert!(self.buffer.len() - self.position >= amt);
        self.position += amt
    }
}

impl Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let internal = self.fill_buf()?;
        let len = std::cmp::min(buf.len(), internal.len());
        if len > 0 {
            buf[..len].copy_from_slice(&internal[..len]);
            self.consume(len);
        }
        Ok(len)
    }
}

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bytes_written = if (buf.len() + self.buffer.len()) > self.buffer.capacity() {
            self.buffer.capacity() - self.buffer.len()
        } else {
            buf.len()
        };
        self.buffer.extend_from_slice(&buf[..bytes_written]);
        if self.buffer.len() == self.buffer.capacity() {
            self.flush()?;
        }
        Ok(bytes_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            Ok(())
        } else {
            let data = std::mem::replace(&mut self.buffer, Vec::with_capacity(self.size));
            match self.sender.send(data) {
                Ok(_) => Ok(()),
                Err(_) => Err(epipe()),
            }
        }
    }
}

pub struct TeeReader<R, W> {
    read: R,
    output: W,
}

impl<R, W> TeeReader<R, W> {
    pub fn new(read: R, output: W) -> Self {
        Self { read, output }
    }

    pub fn into_inner(self) -> (R, W) {
        (self.read, self.output)
    }
}

impl<R: Read, W: Write> Read for TeeReader<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.read.read(buf)?;
        self.output.write_all(&buf[..n])?;
        Ok(n)
    }
}

pub fn all_zeros(buf: &[u8]) -> bool {
    // This processes a lot of data so we iterate
    // by 8 where we can and check the remainder byte wise.
    let (prefix, big, suffix) = unsafe { buf.align_to::<u64>() };
    // Check the fastest part first so we can early exit.
    for v in big {
        if *v != 0 {
            return false;
        }
    }
    for v in prefix {
        if *v != 0 {
            return false;
        }
    }
    for v in suffix {
        if *v != 0 {
            return false;
        }
    }
    true
}
