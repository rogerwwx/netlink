use libc;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::unix::io::RawFd;
use std::ptr;
use std::time::Duration;

const NETLINK_CONNECTOR: i32 = 11; // from linux/netlink.h
const CN_IDX_PROC: u32 = 0x1;
const CN_VAL_PROC: u32 = 0x1;
const PROC_CN_MCAST_LISTEN: u32 = 1;
const PROC_CN_MCAST_IGNORE: u32 = 2;

#[repr(C)]
#[derive(Copy, Clone)]
struct NlMsghdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CbId {
    idx: u32,
    val: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CnMsg {
    id: CbId,
    seq: u32,
    ack: u32,
    len: u16,
    // followed by data (len bytes)
    // alignment/padding handled by layout
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SockAddrNl {
    nl_family: libc::sa_family_t,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

fn create_netlink_socket() -> io::Result<RawFd> {
    // socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR)
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, NETLINK_CONNECTOR) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn bind_proc(fd: RawFd) -> io::Result<()> {
    // bind to CN_IDX_PROC group
    let mut addr: SockAddrNl = unsafe { zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_pad = 0;
    addr.nl_pid = unsafe { libc::getpid() as u32 };
    addr.nl_groups = CN_IDX_PROC;

    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const SockAddrNl as *const libc::sockaddr,
            size_of::<SockAddrNl>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn send_listen(fd: RawFd) -> io::Result<()> {
    // Build message: nlmsghdr + cn_msg + u32(op)
    let nl_hdr_size = size_of::<NlMsghdr>();
    let cn_hdr_size = size_of::<CnMsg>();
    let op_size = size_of::<u32>();
    let total_len = (nl_hdr_size + cn_hdr_size + op_size) as u32;

    let nl_hdr = NlMsghdr {
        nlmsg_len: total_len,
        nlmsg_type: libc::NLMSG_DONE as u16,
        nlmsg_flags: 0,
        nlmsg_seq: 0,
        nlmsg_pid: unsafe { libc::getpid() as u32 },
    };

    let cn_hdr = CnMsg {
        id: CbId {
            idx: CN_IDX_PROC,
            val: CN_VAL_PROC,
        },
        seq: 0,
        ack: 0,
        len: op_size as u16,
    };

    // prepare buffer
    let mut buf = Vec::<u8>::with_capacity(total_len as usize);
    unsafe {
        let p = &nl_hdr as *const NlMsghdr as *const u8;
        buf.extend_from_slice(std::slice::from_raw_parts(p, nl_hdr_size));
        let p2 = &cn_hdr as *const CnMsg as *const u8;
        buf.extend_from_slice(std::slice::from_raw_parts(p2, cn_hdr_size));
        buf.extend_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());
    }

    // sendto
    let ret = unsafe { libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_recv_timeout(fd: RawFd, dur: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: dur.as_secs() as libc::time_t,
        tv_usec: (dur.subsec_micros()) as libc::suseconds_t,
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn recv_one(fd: RawFd) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

fn main() {
    println!("CN_PROC runtime check starting...");

    let fd = match create_netlink_socket() {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("socket creation failed: {}", e);
            return;
        }
    };

    if let Err(e) = bind_proc(fd) {
        eprintln!("bind to CN_IDX_PROC failed: {}", e);
        unsafe { libc::close(fd) };
        return;
    }

    if let Err(e) = send_listen(fd) {
        eprintln!("send listen message failed: {}", e);
        unsafe { libc::close(fd) };
        return;
    }

    // set short recv timeout
    if let Err(e) = set_recv_timeout(fd, Duration::from_secs(3)) {
        eprintln!("setsockopt SO_RCVTIMEO failed: {}", e);
    }

    println!("Subscribed, waiting up to 3s for a proc event (fork/exec/exit)...");
    match recv_one(fd) {
        Ok(buf) => {
            println!(
                "Received {} bytes from netlink. CN_PROC appears available.",
                buf.len()
            );
            // print a short hex preview
            let preview: Vec<String> = buf.iter().take(64).map(|b| format!("{:02x}", b)).collect();
            println!("Data (hex, first bytes): {}", preview.join(" "));
        }
        Err(e) => {
            eprintln!("No event received or recv failed: {}", e);
            eprintln!("CN_PROC may be disabled or events are not being delivered on this system.");
        }
    }

    // cleanup: send ignore (best-effort)
    let _ = unsafe {
        // build ignore message similarly
        let nl_hdr_size = size_of::<NlMsghdr>();
        let cn_hdr_size = size_of::<CnMsg>();
        let op_size = size_of::<u32>();
        let total_len = (nl_hdr_size + cn_hdr_size + op_size) as u32;

        let nl_hdr = NlMsghdr {
            nlmsg_len: total_len,
            nlmsg_type: libc::NLMSG_DONE as u16,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: unsafe { libc::getpid() as u32 },
        };
        let cn_hdr = CnMsg {
            id: CbId {
                idx: CN_IDX_PROC,
                val: CN_VAL_PROC,
            },
            seq: 0,
            ack: 0,
            len: op_size as u16,
        };
        let mut buf = Vec::<u8>::with_capacity(total_len as usize);
        let p = &nl_hdr as *const NlMsghdr as *const u8;
        buf.extend_from_slice(std::slice::from_raw_parts(p, nl_hdr_size));
        let p2 = &cn_hdr as *const CnMsg as *const u8;
        buf.extend_from_slice(std::slice::from_raw_parts(p2, cn_hdr_size));
        buf.extend_from_slice(&PROC_CN_MCAST_IGNORE.to_ne_bytes());
        libc::send(fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0)
    };

    unsafe { libc::close(fd) };
}
