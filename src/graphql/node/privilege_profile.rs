//! Derives the privilege profile of a Clumit Security Sensor from its stored
//! configuration and its "run as root" switch.
//!
//! The input mode is not stored anywhere: it is implied by the `dpdk_args`
//! string of the configuration. This crate does not depend on deploy-core, so
//! a profile is a plain string, which review checks against the build.

use toml::{Table, Value};

const ROOT: &str = "root";
const REPLAY: &str = "replay";
const AF_PACKET: &str = "af-packet";
const DPDK: &str = "dpdk";

const VDEV_PREFIX: &str = "--vdev=";
const AF_PACKET_VDEV_PREFIX: &str = "--vdev=net_af_packet";
const PCAP_VDEV_PREFIX: &str = "--vdev=net_pcap";
const PCI_ADDRESS_FLAG: &str = "-a";

/// Why a configuration selects no privilege profile.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub(super) enum ClassificationError {
    #[error("dpdk_args is not a string")]
    NotAString,
    #[error("the configuration is not TOML")]
    NotToml,
    #[error(
        "dpdk_args selects no input mode (for example live capture with no PCI address, or an \
         empty string)"
    )]
    NoInputMode,
    #[error("dpdk_args selects more than one input mode (a mixed or repeated device list)")]
    MoreThanOneInputMode,
    #[error("dpdk_args names an unsupported virtual device {0}")]
    UnsupportedDevice(String),
}

/// Returns the privilege profile `config` and `run_as_root` derive.
///
/// `run_as_root` decides without the configuration being read. A configuration
/// that names no input mode at all is `replay`, the Web's default mode.
///
/// # Errors
///
/// Returns a [`ClassificationError`] if the configuration is not TOML, if
/// `dpdk_args` is not a string, or if it does not select exactly one supported
/// input mode.
pub(super) fn derive(
    config: Option<&str>,
    run_as_root: bool,
) -> Result<&'static str, ClassificationError> {
    if run_as_root {
        return Ok(ROOT);
    }
    let Some(config) = config.filter(|config| !config.trim().is_empty()) else {
        return Ok(REPLAY);
    };
    let table: Table = config.parse().map_err(|_| ClassificationError::NotToml)?;
    match table.get("dpdk_args") {
        None => match table.get("dpdk_inputs") {
            // The Web reads this shape as live capture.
            Some(Value::Array(inputs)) if !inputs.is_empty() => {
                Err(ClassificationError::NoInputMode)
            }
            _ => Ok(REPLAY),
        },
        Some(Value::String(args)) => classify_args(args),
        Some(_) => Err(ClassificationError::NotAString),
    }
}

fn classify_args(args: &str) -> Result<&'static str, ClassificationError> {
    let (mut af_packet, mut pcap, mut pci_addresses) = (0_usize, 0_usize, 0_usize);
    let mut unsupported = None;
    for token in args.split_ascii_whitespace() {
        if token.starts_with(AF_PACKET_VDEV_PREFIX) {
            af_packet += 1;
        } else if token.starts_with(PCAP_VDEV_PREFIX) {
            pcap += 1;
        } else if token.starts_with(VDEV_PREFIX) {
            unsupported.get_or_insert(token);
        } else if token == PCI_ADDRESS_FLAG {
            pci_addresses += 1;
        }
    }
    if let Some(token) = unsupported {
        return Err(ClassificationError::UnsupportedDevice(token.to_string()));
    }
    match (af_packet, pcap, pci_addresses) {
        (0, 0, 0) => Err(ClassificationError::NoInputMode),
        (1, 0, 0) => Ok(AF_PACKET),
        (0, 1, 0) => Ok(REPLAY),
        (0, 0, _) => Ok(DPDK),
        _ => Err(ClassificationError::MoreThanOneInputMode),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PCAP: &str = "--no-huge -m 256 --no-pci --no-telemetry --no-shconf -l 0 \
                        --vdev=net_pcap0,rx_pcap=../input.pcap";
    const AF: &str = "--in-memory --iova-mode=va --no-pci --no-telemetry -l 0 \
                      --vdev=net_af_packet0,iface=eth1,qpairs=2,blocksz=65536,framesz=2048,\
                      framecnt=32768";
    const LIVE: &str = "--in-memory --no-telemetry -a 0000:01:00.0 -a 0000:01:00.1";

    fn derive_args(args: &str) -> Result<&'static str, ClassificationError> {
        derive(Some(&format!("dpdk_args = \"{args}\"")), false)
    }

    #[test]
    fn dpdk_args_select_their_input_mode() {
        assert_eq!(derive_args(PCAP), Ok(REPLAY));
        assert_eq!(derive_args(AF), Ok(AF_PACKET));
        assert_eq!(derive_args(LIVE), Ok(DPDK));
        assert_eq!(derive_args("-a 0000:01:00.0"), Ok(DPDK));
    }

    #[test]
    fn a_configuration_naming_no_input_mode_is_replay() {
        assert_eq!(derive(None, false), Ok(REPLAY));
        assert_eq!(derive(Some(""), false), Ok(REPLAY));
        assert_eq!(derive(Some(" \n\t"), false), Ok(REPLAY));
        assert_eq!(derive(Some("a = 1"), false), Ok(REPLAY));
        assert_eq!(derive(Some("dpdk_inputs = []"), false), Ok(REPLAY));
    }

    #[test]
    fn dpdk_inputs_without_dpdk_args_is_refused() {
        assert_eq!(
            derive(Some("dpdk_inputs = [\"0000:01:00.0\"]"), false),
            Err(ClassificationError::NoInputMode)
        );
    }

    #[test]
    fn the_switch_decides_without_reading_the_configuration() {
        for config in [
            None,
            Some(""),
            Some("a = 1"),
            Some("not toml ="),
            Some("dpdk_args = 1"),
            Some("dpdk_args = \"--vdev=net_null0\""),
        ] {
            assert_eq!(derive(config, true), Ok(ROOT));
        }
    }

    #[test]
    fn dpdk_args_with_no_input_mode_are_refused() {
        assert_eq!(
            derive_args("--in-memory --no-telemetry"),
            Err(ClassificationError::NoInputMode)
        );
        assert_eq!(derive_args(""), Err(ClassificationError::NoInputMode));
    }

    #[test]
    fn dpdk_args_with_more_than_one_input_mode_are_refused() {
        for args in [
            "--vdev=net_pcap0,rx_pcap=a --vdev=net_af_packet0,iface=eth1",
            "--vdev=net_pcap0,rx_pcap=a -a 0000:01:00.0",
            "--vdev=net_af_packet0,iface=eth1 -a 0000:01:00.0",
            "--vdev=net_af_packet0,iface=eth1 --vdev=net_af_packet1,iface=eth2",
            "--vdev=net_pcap0,rx_pcap=a --vdev=net_pcap1,rx_pcap=b",
        ] {
            assert_eq!(
                derive_args(args),
                Err(ClassificationError::MoreThanOneInputMode),
                "{args}"
            );
        }
    }

    #[test]
    fn an_unsupported_virtual_device_is_named() {
        let unsupported = Err(ClassificationError::UnsupportedDevice(
            "--vdev=net_null0".to_string(),
        ));
        assert_eq!(derive_args("--vdev=net_null0"), unsupported);
        assert_eq!(
            derive_args("--vdev=net_null0 --vdev=net_pcap0,rx_pcap=a"),
            unsupported
        );
    }

    #[test]
    fn a_dpdk_args_that_is_not_a_string_is_refused() {
        for config in ["dpdk_args = 1", "dpdk_args = [\"-a\"]"] {
            assert_eq!(
                derive(Some(config), false),
                Err(ClassificationError::NotAString),
                "{config}"
            );
        }
    }

    #[test]
    fn a_configuration_that_is_not_toml_is_refused() {
        assert_eq!(
            derive(Some("not toml ="), false),
            Err(ClassificationError::NotToml)
        );
    }

    #[test]
    fn each_error_names_its_problem() {
        for (error, expected) in [
            (ClassificationError::NotAString, "dpdk_args is not a string"),
            (
                ClassificationError::NotToml,
                "the configuration is not TOML",
            ),
            (
                ClassificationError::UnsupportedDevice("--vdev=net_null0".to_string()),
                "dpdk_args names an unsupported virtual device --vdev=net_null0",
            ),
        ] {
            assert_eq!(error.to_string(), expected);
        }
        assert!(
            ClassificationError::NoInputMode
                .to_string()
                .starts_with("dpdk_args selects no input mode")
        );
        assert!(
            ClassificationError::MoreThanOneInputMode
                .to_string()
                .starts_with("dpdk_args selects more than one input mode")
        );
    }
}
