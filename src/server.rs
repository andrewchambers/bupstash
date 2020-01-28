/*
use super::protocol;
use super::store;

pub struct ServerConfig {
    store_path: std::path::PathBuf,
}

pub fn serve(
    cfg: ServerConfig,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    protocol::send_server_info(
        w,
        &protocol::ServerInfo {
            protocol_version: "0".to_string(),
        },
    )?;

    match protocol::read_packet(r)? {
        (protocol::PacketKind::BeginSend, buf) => {
            drop(buf);
            let mut store = store::Store::open(&cfg.store_path)?;
            recv(cfg, &mut store, r, w)
        }
        _ => Err(failure::format_err!(
            "protocol error, unexpected packet kind"
        )),
    }
}

fn recv(
    cfg: ServerConfig,
    store: &mut store::Store,
    r: &mut dyn std::io::Read,
    w: &mut dyn std::io::Write,
) -> Result<(), failure::Error> {
    protocol::send_ack_send(
        w,
        &protocol::AckSend {
            gc_generation: store.gc_generation.clone(),
        },
    )?;

    loop {
        match protocol::read_packet(r)? {
            (protocol::PacketKind::Chunk, buf) => {
                let chunk = protocol::decode_chunk(buf)?;
                store.add_chunk(chunk.address, chunk.data)?;
                panic!("TODO");
            }
            (protocol::PacketKind::CommitSend, _buf) => {
                store.sync()?;
                panic!("TODO");
            }
            _ => {
                return Err(failure::format_err!(
                    "protocol error, unexpected packet kind"
                ))
            }
        }
    }

    Ok(())
}

*/
