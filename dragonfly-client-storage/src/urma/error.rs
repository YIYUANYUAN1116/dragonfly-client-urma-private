use std::fmt;
use std::time::Duration;

use super::ffi::FfiError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    AlreadyInitialized,
    InvalidConfiguration(String),
    Protocol(String),
    PeerRejected {
        code: u32,
        message: String,
    },
    ControlTimeout {
        operation: &'static str,
    },
    StartupTimeout {
        timeout: Duration,
    },
    OperationTimeout {
        sequence: Option<u64>,
    },
    BufferUnavailable {
        kind: &'static str,
        requested: usize,
        available: usize,
    },
    Completion {
        status: i32,
        opcode: u32,
        user_ctx: u64,
        sequence: Option<u64>,
        post_call: Option<u64>,
    },
    StartupRollback {
        primary: Box<Error>,
        cleanup_failures: Vec<String>,
    },
    Shutdown {
        failures: Vec<String>,
    },
    Native {
        operation: &'static str,
        failure: NativeFailure,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeFailure {
    Contract(&'static str),
    MissingHandle,
    Status(i32),
    Import {
        stage: u32,
        native_status: i32,
        system_errno: i32,
        tp_count: u32,
        tp_handle: u64,
        tx_psn: u32,
        local_eid: [u8; super::ffi::EID_SIZE],
        peer_eid: [u8; super::ffi::EID_SIZE],
    },
}

pub(crate) fn native_error(operation: &'static str, error: FfiError) -> Error {
    let failure = match error {
        FfiError::Contract(detail) => NativeFailure::Contract(detail),
        FfiError::NullHandle => NativeFailure::MissingHandle,
        FfiError::Status(status) => NativeFailure::Status(status),
        FfiError::Import(failure) => NativeFailure::Import {
            stage: failure.stage,
            native_status: failure.native_status,
            system_errno: failure.system_errno,
            tp_count: failure.tp_count,
            tp_handle: failure.tp_handle,
            tx_psn: failure.tx_psn,
            local_eid: failure.local_eid,
            peer_eid: failure.peer_eid,
        },
    };
    Error::Native { operation, failure }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInitialized => {
                write!(f, "an URMA runtime already owns process-global liburma")
            }
            Self::InvalidConfiguration(detail) => write!(f, "invalid configuration: {detail}"),
            Self::Protocol(detail) => write!(f, "protocol error: {detail}"),
            Self::PeerRejected { code, message } => {
                write!(
                    f,
                    "URMA peer rejected request: code={code} message={message}"
                )
            }
            Self::ControlTimeout { operation } => {
                write!(f, "URMA control operation timed out: {operation}")
            }
            Self::StartupTimeout { timeout } => {
                write!(f, "URMA Fabric startup timed out after {timeout:?}")
            }
            Self::OperationTimeout { sequence } => {
                write!(f, "URMA operation timed out: sequence={sequence:?}")
            }
            Self::BufferUnavailable {
                kind,
                requested,
                available,
            } => write!(
                f,
                "URMA {kind} buffer unavailable: requested={requested} available={available}"
            ),
            Self::Completion {
                status,
                opcode,
                user_ctx,
                sequence,
                post_call,
            } => {
                let status_name = match *status {
                    0 => "SUCCESS",
                    1 => "UNSUPPORTED_OPCODE_ERR",
                    2 => "LOC_LEN_ERR",
                    3 => "LOC_OPERATION_ERR",
                    4 => "LOC_ACCESS_ERR",
                    5 => "REM_RESP_LEN_ERR",
                    6 => "REM_UNSUPPORTED_REQ_ERR",
                    7 => "REM_OPERATION_ERR",
                    8 => "REM_ACCESS_ABORT_ERR",
                    9 => "ACK_TIMEOUT_ERR",
                    10 => "RNR_RETRY_CNT_EXC_ERR",
                    11 => "WR_FLUSH_ERR",
                    12 => "WR_SUSPEND_DONE",
                    13 => "WR_FLUSH_ERR_DONE",
                    14 => "WR_UNHANDLED",
                    15 => "LOC_DATA_POISON",
                    16 => "REM_DATA_POISON",
                    _ => "UNKNOWN",
                };
                write!(
                    f,
                    "completion failed: status={status}({status_name}), opcode={opcode}, user_ctx={user_ctx}, sequence={sequence:?}, post_call={post_call:?}"
                )
            }
            Self::StartupRollback {
                primary,
                cleanup_failures,
            } => write!(
                f,
                "startup failed: {primary}; rollback failures: {}",
                cleanup_failures.join("; ")
            ),
            Self::Shutdown { failures } => {
                write!(f, "shutdown failures: {}", failures.join("; "))
            }
            Self::Native { operation, failure } => match failure {
                NativeFailure::Contract(detail) => {
                    write!(f, "FFI contract violation during {operation}: {detail}")
                }
                NativeFailure::MissingHandle => write!(
                    f,
                    "native operation {operation} succeeded without returning a handle"
                ),
                NativeFailure::Status(status) => {
                    if *status < 0 {
                        write!(
                            f,
                            "liburma operation {operation} failed with status {status} ({})",
                            std::io::Error::from_raw_os_error(-status)
                        )
                    } else {
                        write!(
                            f,
                            "liburma operation {operation} failed with status {status}"
                        )
                    }
                }
                NativeFailure::Import {
                    stage,
                    native_status,
                    system_errno,
                    tp_count,
                    tp_handle,
                    tx_psn,
                    local_eid,
                    peer_eid,
                } => write!(
                    f,
                    "liburma operation {operation} failed during {}: status={} errno={} ({}) tp_count={} tp_handle={} tx_psn={} local_eid={} peer_eid={}",
                    import_stage_name(*stage),
                    native_status,
                    system_errno,
                    std::io::Error::from_raw_os_error(*system_errno),
                    tp_count,
                    tp_handle,
                    tx_psn,
                    format_eid(local_eid),
                    format_eid(peer_eid),
                ),
            },
        }
    }
}

fn import_stage_name(stage: u32) -> &'static str {
    match stage {
        super::ffi::IMPORT_STAGE_GET_TP => "get_tp_list",
        super::ffi::IMPORT_STAGE_IMPORT_EX => "import_jetty_ex",
        super::ffi::IMPORT_STAGE_IMPORT => "import_jetty",
        _ => "validation",
    }
}

fn format_eid(eid: &[u8; super::ffi::EID_SIZE]) -> String {
    eid.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_native_status_includes_errno_text() {
        let error = native_error("import_jetty", FfiError::Status(-1));
        let display = error.to_string();
        assert!(display.contains("status -1"));
        assert!(display.contains("Operation not permitted"));
    }

    #[test]
    fn import_failure_identifies_provider_stage_and_connection_metadata() {
        let error = native_error(
            "import_jetty",
            FfiError::Import(super::super::ffi::ImportFailure {
                stage: super::super::ffi::IMPORT_STAGE_IMPORT_EX,
                native_status: -1,
                system_errno: 1,
                tp_count: 1,
                tp_handle: 42,
                tx_psn: 7,
                local_eid: [0x11; super::super::ffi::EID_SIZE],
                peer_eid: [0x22; super::super::ffi::EID_SIZE],
            }),
        );
        let display = error.to_string();
        assert!(display.contains("during import_jetty_ex"));
        assert!(display.contains("tp_count=1 tp_handle=42 tx_psn=7"));
        assert!(display.contains("local_eid=11111111111111111111111111111111"));
        assert!(display.contains("peer_eid=22222222222222222222222222222222"));
    }
}
