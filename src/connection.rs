//! # Connection
//! This module contains the general API for the conntrack library.

use neli::{
    consts::{nl::*, socket::*},
    genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder},
    nl::{NlPayload, Nlmsghdr},
    router::synchronous::NlRouter,
    types::{Buffer, GenlBuffer},
    utils::Groups,
};

use crate::attributes::*;
use crate::decoders::*;
use crate::message::*;
use crate::model::*;
use crate::result::*;

/// The `Conntrack` type is used to connect to a netfilter socket and execute
/// conntrack table specific commands.
pub struct Conntrack {
    socket: NlRouter,
}

impl Conntrack {
    /// This method opens a netfilter socket using a `socket()` syscall, and
    /// returns the `Conntrack` instance on success.
    pub fn connect() -> Result<Self> {
        let socket = NlRouter::connect(NlFamily::Netfilter, Some(0), Groups::empty())?.0;
        Ok(Self { socket })
    }

    /// The dump call will list all connection tracking for the `Conntrack` table as a
    /// `Vec<Flow>` instances.
    pub fn dump(&self) -> Result<Vec<Flow>> {
        let genlhdr = GenlmsghdrBuilder::default()
            .cmd(0u8)
            .version(libc::NFNETLINK_V0 as u8)
            .attrs(GenlBuffer::<ConntrackAttr, Buffer>::new())
            .build()?;

        let recv_iter = self.socket.send(
            CtNetlinkMessage::Conntrack,
            NlmF::DUMP,
            NlPayload::Payload(genlhdr),
        )?;

        let mut flows = Vec::new();

        for result in recv_iter {
            let result: Nlmsghdr<CtNetlinkMessage, Genlmsghdr<u8, ConntrackAttr>> = result?;
            if let NlPayload::Payload(message) = result.nl_payload() {
                let handle = message.attrs().get_attr_handle();

                flows.push(Flow::decode(handle)?);
            }
        }

        Ok(flows)
    }

    /// Set or update the mark on an existing conntrack entry by its `id` in the default zone (0).
    pub fn set_mark(&self, id: u32, mark: u32, mark_mask: Option<u32>) -> Result<()> {
        self.set_mark_in_zone(id, None, mark, mark_mask)
    }

    /// Set or update the mark on an existing conntrack entry by its `id` and optional `zone`.
    pub fn set_mark_in_zone(
        &self,
        id: u32,
        zone: Option<u16>,
        mark: u32,
        mark_mask: Option<u32>,
    ) -> Result<()> {
        let mut attrs = GenlBuffer::<ConntrackAttr, Buffer>::new();

        let build_u32_attr = |attr: ConntrackAttr, value: u32| -> Result<_> {
            let attr_type = AttrTypeBuilder::default()
                .nla_type(attr)
                .nla_network_order(true)
                .build()?;

            let mut payload = Buffer::new();
            payload.extend_from_slice(&value.to_be_bytes());

            Ok(NlattrBuilder::default()
                .nla_type(attr_type)
                .nla_payload(payload)
                .build()?)
        };

        let build_u16_attr = |attr: ConntrackAttr, value: u16| -> Result<_> {
            let attr_type = AttrTypeBuilder::default()
                .nla_type(attr)
                .nla_network_order(true)
                .build()?;

            let mut payload = Buffer::new();
            payload.extend_from_slice(&value.to_be_bytes());

            Ok(NlattrBuilder::default()
                .nla_type(attr_type)
                .nla_payload(payload)
                .build()?)
        };

        attrs.push(build_u32_attr(ConntrackAttr::CtaId, id)?);

        if let Some(zone) = zone {
            attrs.push(build_u16_attr(ConntrackAttr::CtaZone, zone)?);
        }

        attrs.push(build_u32_attr(ConntrackAttr::CtaMark, mark)?);

        // Kernel expects a mask when updating marks; default to all bits if none provided.
        let effective_mask = mark_mask.unwrap_or(u32::MAX);
        attrs.push(build_u32_attr(ConntrackAttr::CtaMarkMask, effective_mask)?);

        let genlhdr = GenlmsghdrBuilder::default()
            .cmd(0u8)
            .version(libc::NFNETLINK_V0 as u8)
            .attrs(attrs)
            .build()?;

        let responses = self.socket.send(
            CtNetlinkMessage::ConntrackNew,
            NlmF::ACK | NlmF::REQUEST | NlmF::REPLACE,
            NlPayload::Payload(genlhdr),
        )?;

        for response in responses {
            let _: Nlmsghdr<CtNetlinkMessage, Genlmsghdr<u8, ConntrackAttr>> = response?;
        }

        Ok(())
    }
}
