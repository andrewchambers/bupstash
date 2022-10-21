use std::sync::atomic;

pub struct UsageReporter {
    mq: posixmq::PosixMq,
    usage_tag: String,
    chunks_added: atomic::AtomicU64,
    bytes_added: atomic::AtomicU64,
}

impl UsageReporter {
    pub fn from_env() -> Result<UsageReporter, anyhow::Error> {
        let usage_tag = match std::env::var("BUPSTASH_USAGE_TAG") {
            Ok(usage_tag) => serde_json::to_string(&usage_tag)?,
            Err(_) => anyhow::bail!("env var BUPSTASH_USAGE_TAG is missing"),
        };

        let mq = match posixmq::OpenOptions::writeonly()
            .existing()
            .open("/bupstash_usage")
        {
            Ok(mq) => mq,
            Err(err) => anyhow::bail!("unable to open metering message queue: {}", err),
        };

        Ok(UsageReporter {
            usage_tag,
            mq,
            chunks_added: atomic::AtomicU64::new(0),
            bytes_added: atomic::AtomicU64::new(0),
        })
    }

    pub fn chunk_added(&self, chunk_bytes: u64) {
        self.chunks_added.fetch_add(1, atomic::Ordering::SeqCst);
        self.bytes_added
            .fetch_add(chunk_bytes, atomic::Ordering::SeqCst);
    }

    pub fn set_storage_totals(
        &self,
        total_bytes: u64,
        total_chunks: u64,
    ) -> Result<(), anyhow::Error> {
        self.chunks_added.store(0, atomic::Ordering::SeqCst);
        self.bytes_added.store(0, atomic::Ordering::SeqCst);
        let payload = format!(
            "{{{}:{{\"b\":{{\"op\":\"set\",\"count\":{}}},\"ch\":{{\"op\":\"set\",\"count\":{}}}}}}}",
            self.usage_tag, total_bytes, total_chunks,
        );
        self.send_payload(payload)?;
        Ok(())
    }

    pub fn flush(&self) -> Result<(), anyhow::Error> {
        let bytes_added = self.bytes_added.swap(0, atomic::Ordering::SeqCst);
        let chunks_added = self.chunks_added.swap(0, atomic::Ordering::SeqCst);
        if bytes_added == 0 && chunks_added == 0 {
            return Ok(());
        }
        let payload = format!(
            "{{{}:{{\"b\":{{\"count\":{}}},\"ch\":{{\"count\":{}}}}}}}",
            self.usage_tag, bytes_added, chunks_added,
        );
        self.send_payload(payload)?;
        Ok(())
    }

    fn send_payload(&self, payload: String) -> Result<(), anyhow::Error> {
        self.mq.send(1, payload.as_bytes())?;
        Ok(())
    }
}
