use std::fmt;

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
}

pub(crate) fn native_error(operation: &'static str, error: FfiError) -> Error {
    let failure = match error {
        FfiError::Contract(detail) => NativeFailure::Contract(detail),
        FfiError::NullHandle => NativeFailure::MissingHandle,
        FfiError::Status(status) => NativeFailure::Status(status),
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
                    write!(
                        f,
                        "liburma operation {operation} failed with status {status}"
                    )
                }
            },
        }
    }
}

impl std::error::Error for Error {}
