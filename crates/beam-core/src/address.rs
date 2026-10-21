//! VLESS and XUDP address encoding.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Address type values used by VLESS and XUDP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    /// IPv4 address.
    Ipv4 = 1,
    /// Domain name.
    Domain = 2,
    /// IPv6 address.
    Ipv6 = 3,
}

/// A destination address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// IPv4 address.
    Ipv4(Ipv4Addr),
    /// Domain name.
    Domain(String),
    /// IPv6 address.
    Ipv6(Ipv6Addr),
}

/// A destination address and port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetLocation {
    /// Destination address.
    pub address: Address,
    /// Destination port.
    pub port: u16,
}

/// Errors returned while parsing or encoding an address.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    /// The input ended before the address was complete.
    #[error("truncated address")]
    Truncated,
    /// The address type is not 1, 2, or 3.
    #[error("unsupported address type {0}")]
    UnsupportedType(u8),
    /// A domain name is empty or longer than 255 bytes.
    #[error("invalid domain length {0}")]
    InvalidDomainLength(usize),
    /// A domain name is not valid UTF-8.
    #[error("domain name is not valid UTF-8")]
    InvalidDomain,
    /// A parsed address could not be represented.
    #[error("invalid address")]
    InvalidAddress,
}

impl NetLocation {
    /// Parses `port(2) | atyp(1) | address` and returns the value plus the
    /// remaining bytes.
    pub fn parse_port_address(input: &[u8]) -> Result<(Self, &[u8]), AddressError> {
        let (port_bytes, rest) = input
            .split_first_chunk::<2>()
            .ok_or(AddressError::Truncated)?;
        let port = u16::from_be_bytes(*port_bytes);
        let (&address_type, rest) = rest.split_first().ok_or(AddressError::Truncated)?;
        let (address, rest) = Address::parse(address_type, rest)?;
        Ok((Self { address, port }, rest))
    }

    /// Encodes this location as `port(2) | atyp(1) | address`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), AddressError> {
        out.extend_from_slice(&self.port.to_be_bytes());
        self.address.encode(out)
    }
}

impl Address {
    /// Parses an address of `address_type` and returns the value plus the
    /// remaining bytes.
    pub fn parse(address_type: u8, input: &[u8]) -> Result<(Self, &[u8]), AddressError> {
        match address_type {
            1 => {
                let (bytes, rest) = input
                    .split_first_chunk::<4>()
                    .ok_or(AddressError::Truncated)?;
                Ok((Self::Ipv4(Ipv4Addr::from(*bytes)), rest))
            }
            2 => {
                let (&length, rest) = input.split_first().ok_or(AddressError::Truncated)?;
                let length = usize::from(length);
                if length == 0 {
                    return Err(AddressError::InvalidDomainLength(0));
                }
                let (domain, rest) = rest
                    .split_at_checked(length)
                    .ok_or(AddressError::Truncated)?;
                let domain = std::str::from_utf8(domain)
                    .map_err(|_| AddressError::InvalidDomain)?
                    .to_owned();
                Ok((Self::Domain(domain), rest))
            }
            3 => {
                let (bytes, rest) = input
                    .split_first_chunk::<16>()
                    .ok_or(AddressError::Truncated)?;
                Ok((Self::Ipv6(Ipv6Addr::from(*bytes)), rest))
            }
            other => Err(AddressError::UnsupportedType(other)),
        }
    }

    /// Encodes this address as `atyp(1) | address`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), AddressError> {
        match self {
            Self::Ipv4(address) => {
                out.push(AddressType::Ipv4 as u8);
                out.extend_from_slice(&address.octets());
            }
            Self::Domain(domain) => {
                let length = u8::try_from(domain.len())
                    .map_err(|_| AddressError::InvalidDomainLength(domain.len()))?;
                if length == 0 {
                    return Err(AddressError::InvalidDomainLength(0));
                }
                out.push(AddressType::Domain as u8);
                out.push(length);
                out.extend_from_slice(domain.as_bytes());
            }
            Self::Ipv6(address) => {
                out.push(AddressType::Ipv6 as u8);
                out.extend_from_slice(&address.octets());
            }
        }
        Ok(())
    }

    /// Returns the address type byte.
    pub fn address_type(&self) -> AddressType {
        match self {
            Self::Ipv4(_) => AddressType::Ipv4,
            Self::Domain(_) => AddressType::Domain,
            Self::Ipv6(_) => AddressType::Ipv6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Address, AddressError, NetLocation};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_and_encodes_ipv4() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&443_u16.to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&[192, 0, 2, 1]);
        bytes.extend_from_slice(b"tail");

        let (location, rest) = NetLocation::parse_port_address(&bytes).unwrap();
        assert_eq!(
            location,
            NetLocation {
                address: Address::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                port: 443,
            }
        );
        assert_eq!(rest, b"tail");

        let mut encoded = Vec::new();
        location.encode(&mut encoded).unwrap();
        assert_eq!(encoded, &bytes[..bytes.len() - 4]);
    }

    #[test]
    fn parses_and_encodes_ipv6() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&8443_u16.to_be_bytes());
        bytes.push(3);
        bytes.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());

        let (location, rest) = NetLocation::parse_port_address(&bytes).unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            location,
            NetLocation {
                address: Address::Ipv6(Ipv6Addr::LOCALHOST),
                port: 8443,
            }
        );

        let mut encoded = Vec::new();
        location.encode(&mut encoded).unwrap();
        assert_eq!(encoded, bytes);
    }

    #[test]
    fn parses_and_encodes_domain() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&53_u16.to_be_bytes());
        bytes.push(2);
        bytes.push(11);
        bytes.extend_from_slice(b"example.com");

        let (location, rest) = NetLocation::parse_port_address(&bytes).unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            location,
            NetLocation {
                address: Address::Domain("example.com".to_owned()),
                port: 53,
            }
        );

        let mut encoded = Vec::new();
        location.encode(&mut encoded).unwrap();
        assert_eq!(encoded, bytes);
    }

    #[test]
    fn rejects_oversized_domain_on_encode() {
        let address = Address::Domain("a".repeat(256));
        let mut encoded = Vec::new();
        assert_eq!(
            address.encode(&mut encoded),
            Err(AddressError::InvalidDomainLength(256))
        );
    }

    #[test]
    fn rejects_truncated_and_invalid_inputs() {
        assert_eq!(
            NetLocation::parse_port_address(&[0, 80]),
            Err(AddressError::Truncated)
        );
        assert_eq!(
            NetLocation::parse_port_address(&[0, 80, 4]),
            Err(AddressError::UnsupportedType(4))
        );
        assert_eq!(
            NetLocation::parse_port_address(&[0, 80, 1, 127, 0]),
            Err(AddressError::Truncated)
        );
        assert_eq!(
            NetLocation::parse_port_address(&[0, 80, 2, 0]),
            Err(AddressError::InvalidDomainLength(0))
        );
    }
}
