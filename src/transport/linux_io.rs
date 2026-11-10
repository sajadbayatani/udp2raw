//! Linux control messages used to preserve the destination address of wildcard
//! listeners. A reply must use the same address on a multihomed server.
use socket2::{SockAddr, Socket};
use std::{
    io,
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::{AsRawFd, RawFd},
    ptr,
};
use tokio::{io::Interest, net::UdpSocket};

pub(super) fn set_int(fd: RawFd, level: i32, option: i32, value: i32) -> io::Result<()> {
    // SAFETY: the kernel copies a single int from the live stack value.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&value as *const i32).cast(),
            mem::size_of::<i32>() as _,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn bind_packet_device(socket: &Socket, name: &str, protocol: u16) -> io::Result<()> {
    let name = std::ffi::CString::new(name)?;
    // SAFETY: the interface name is NUL terminated. bind copies the initialized
    // Linux packet address, which is valid for this AF_PACKET socket.
    unsafe {
        let index = libc::if_nametoindex(name.as_ptr());
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_ll = mem::zeroed();
        addr.sll_family = libc::AF_PACKET as _;
        addr.sll_protocol = protocol.to_be();
        addr.sll_ifindex = index as _;
        let rc = libc::bind(
            socket.as_raw_fd(),
            (&addr as *const libc::sockaddr_ll).cast(),
            mem::size_of_val(&addr) as _,
        );
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

pub(super) fn pktinfo(socket: &Socket, v6: bool) -> io::Result<()> {
    let (level, opt) = if v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    } else {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    };
    set_int(socket.as_raw_fd(), level, opt, 1)
}

pub(super) async fn recv(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, IpAddr)> {
    socket
        .async_io(Interest::READABLE, || {
            // Use usize alignment for cmsghdr and an owned sockaddr_storage for the sender.
            let mut control = [0usize; 12];
            let mut addr = MaybeUninit::<libc::sockaddr_storage>::zeroed();
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            };
            // SAFETY: recvmsg only writes to the buffers named in msg; their lifetimes
            // cover the call and cmsg iteration.
            unsafe {
                let mut msg: libc::msghdr = mem::zeroed();
                msg.msg_name = addr.as_mut_ptr().cast();
                msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as _;
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = control.as_mut_ptr().cast();
                msg.msg_controllen = mem::size_of_val(&control) as _;
                let n = libc::recvmsg(socket.as_raw_fd(), &mut msg, 0);
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                let src = match (*addr.as_ptr()).ss_family as i32 {
                    libc::AF_INET => {
                        let addr = &*addr.as_ptr().cast::<libc::sockaddr_in>();
                        SocketAddr::new(
                            Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()).into(),
                            u16::from_be(addr.sin_port),
                        )
                    }
                    libc::AF_INET6 => {
                        let addr = &*addr.as_ptr().cast::<libc::sockaddr_in6>();
                        SocketAddr::V6(std::net::SocketAddrV6::new(
                            Ipv6Addr::from(addr.sin6_addr.s6_addr),
                            u16::from_be(addr.sin6_port),
                            0,
                            addr.sin6_scope_id,
                        ))
                    }
                    _ => return Err(io::Error::other("expected IP socket address")),
                };
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::IPPROTO_IP
                        && (*cmsg).cmsg_type == libc::IP_PKTINFO
                    {
                        let info =
                            ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in_pktinfo>());
                        return Ok((
                            n as usize,
                            src,
                            IpAddr::V4(Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes())),
                        ));
                    }
                    if (*cmsg).cmsg_level == libc::IPPROTO_IPV6
                        && (*cmsg).cmsg_type == libc::IPV6_PKTINFO
                    {
                        let info =
                            ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in6_pktinfo>());
                        let mut src = src;
                        if let SocketAddr::V6(ref mut v6) = src {
                            if v6.ip().is_unicast_link_local() {
                                v6.set_scope_id(info.ipi6_ifindex);
                            }
                        }
                        return Ok((
                            n as usize,
                            src,
                            IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)),
                        ));
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
                Err(io::Error::other("missing destination packet info"))
            }
        })
        .await
}

pub(super) async fn send_udp(
    socket: &UdpSocket,
    dst: SocketAddr,
    src: IpAddr,
    bytes: &[u8],
) -> io::Result<()> {
    let dst = SockAddr::from(dst);
    socket
        .async_io(Interest::WRITABLE, || {
            let mut iov = libc::iovec {
                iov_base: bytes.as_ptr().cast_mut().cast(),
                iov_len: bytes.len(),
            };
            let mut control = [0usize; 12];
            // SAFETY: sendmsg reads the named iovec and the explicitly sized, aligned
            // ancillary buffer. The buffers remain live throughout the syscall.
            unsafe {
                let mut msg: libc::msghdr = mem::zeroed();
                msg.msg_name = dst.as_ptr().cast_mut().cast();
                msg.msg_namelen = dst.len();
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = control.as_mut_ptr().cast();
                let size = match src {
                    IpAddr::V4(_) => mem::size_of::<libc::in_pktinfo>(),
                    IpAddr::V6(_) => mem::size_of::<libc::in6_pktinfo>(),
                };
                msg.msg_controllen = libc::CMSG_SPACE(size as _) as _;
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_len = libc::CMSG_LEN(size as _) as _;
                match src {
                    IpAddr::V4(ip) => {
                        (*cmsg).cmsg_level = libc::IPPROTO_IP;
                        (*cmsg).cmsg_type = libc::IP_PKTINFO;
                        let mut info: libc::in_pktinfo = mem::zeroed();
                        info.ipi_spec_dst.s_addr = u32::from_ne_bytes(ip.octets());
                        ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast(), info);
                    }
                    IpAddr::V6(ip) => {
                        (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                        (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                        let mut info: libc::in6_pktinfo = mem::zeroed();
                        info.ipi6_addr.s6_addr = ip.octets();
                        ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast(), info);
                    }
                }
                if libc::sendmsg(socket.as_raw_fd(), &msg, 0) < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            }
        })
        .await
}

// Classic socket BPF: reject unrelated packets before allocating/copying an IP payload.
pub(super) fn filter(
    socket: &Socket,
    mode: crate::config::Mode,
    server: bool,
    port: u16,
    v6: bool,
    link: bool,
) -> io::Result<()> {
    use crate::config::Mode;
    let mut prog = Vec::new();
    let stmt = |code: u16, k: u32| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    };
    let accept = stmt(0x06, 0xffff_ffff);
    let reject = stmt(0x06, 0);
    // X names the transport offset; IPv6 raw payloads already have the IP header removed.
    if link {
        prog.push(stmt(0x30, if v6 { 6 } else { 9 })); // LD B ABS
        if v6 {
            // Known extension types bypass the fixed-offset transport check.
            let extensions = [0, 43, 44, 51, 60];
            prog.push(jeq(crate::packet::protocol(mode, true).into(), 7, 0));
            for (index, next) in extensions.into_iter().enumerate() {
                prog.push(jeq(next, (extensions.len() - index) as u8, 0));
            }
            prog.push(reject);
            prog.push(accept);
        } else {
            prog.push(jeq(crate::packet::protocol(mode, false).into(), 1, 0));
            prog.push(reject);
        }
    }
    prog.push(if v6 {
        stmt(0x01, if link { 40 } else { 0 })
    } else {
        stmt(0xb1, 0)
    }); // LDX IMM or LDX B MSH
    if mode == Mode::Icmp {
        let ty = match (v6, server) {
            (true, true) => 128,
            (true, false) => 129,
            (false, true) => 8,
            (false, false) => 0,
        };
        prog.extend([stmt(0x50, 0), jeq(ty, 1, 0), reject]); // LD B IND
        if !server {
            prog.extend([stmt(0x48, 4), jeq(port.into(), 1, 0), reject]);
        }
    } else {
        prog.extend([stmt(0x48, 2), jeq(port.into(), 1, 0), reject]); // LD H IND destination port
    }
    prog.push(accept);
    let mut f = libc::sock_fprog {
        len: prog.len() as _,
        filter: prog.as_mut_ptr(),
    };
    // SAFETY: Linux copies the validated program before setsockopt returns.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&mut f as *mut libc::sock_fprog).cast(),
            mem::size_of_val(&f) as _,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
