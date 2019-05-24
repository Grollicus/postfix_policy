use std::io::{BufRead, Write};

#[derive(Debug)]
pub enum PostfixPolicyError {
    IoError(std::io::Error),
    InvalidLine(Vec<u8>),
}

impl std::convert::From<std::io::Error> for PostfixPolicyError {
    fn from(e: std::io::Error) -> PostfixPolicyError {
        PostfixPolicyError::IoError(e)
    }
}

#[derive(Debug, PartialEq)]
pub enum PolicyResponse {
    Ok,
    Reject(Vec<u8>),
    Defer(Vec<u8>),
    DeferIfReject(Vec<u8>),
    DeferIfPermit(Vec<u8>),
    Bcc(Vec<u8>),
    Discard(Vec<u8>),
    Dunno,
    Hold(Vec<u8>),
    Redirect(Vec<u8>),
    Info(Vec<u8>),
    Warn(Vec<u8>),
}

pub trait PolicyRequestHandler<'l, T> {
    fn new(ctx: &'l T) -> Self;
    fn parse_line(&mut self, name: &[u8], value: &[u8]);

    fn response(self) -> PolicyResponse;
}

fn serialize_response(resp: PolicyResponse) -> Vec<u8> {
    let mut message = Vec::new();
    let action: &[u8] = match resp {
        PolicyResponse::Ok => b"OK",
        PolicyResponse::Reject(msg) => {
            message = msg;
            b"REJECT"
        }
        PolicyResponse::Defer(msg) => {
            message = msg;
            b"DEFER"
        }
        PolicyResponse::DeferIfReject(msg) => {
            message = msg;
            b"DEFER_IF_REJECT"
        }
        PolicyResponse::DeferIfPermit(msg) => {
            message = msg;
            b"DEFER_IF_PERMIT"
        }
        PolicyResponse::Bcc(email) => {
            message = email;
            b"BCC"
        }
        PolicyResponse::Discard(msg) => {
            message = msg;
            b"DISCARD"
        }
        PolicyResponse::Dunno => b"DUNNO",
        PolicyResponse::Hold(msg) => {
            message = msg;
            b"HOLD"
        }
        PolicyResponse::Redirect(dst) => {
            message = dst;
            b"REDIRECT"
        }
        PolicyResponse::Info(msg) => {
            message = msg;
            b"INFO"
        }
        PolicyResponse::Warn(msg) => {
            message = msg;
            b"WARN"
        }
    };
    let mut resp = Vec::from(action);
    if message.len() != 0 {
        resp.push(b' ');
        resp.extend_from_slice(&message);
    }
    resp
}

#[test]
fn test_serialize_response() {
    assert_eq!(b"OK"[..], serialize_response(PolicyResponse::Ok)[..]);
    assert_eq!(
        b"REJECT"[..],
        serialize_response(PolicyResponse::Reject(Vec::new()))[..]
    );
    assert_eq!(
        b"REJECT asdf"[..],
        serialize_response(PolicyResponse::Reject(b"asdf".to_vec()))[..]
    );
    assert_eq!(b"DEFER"[..], serialize_response(PolicyResponse::Defer(Vec::new()))[..]);
    assert_eq!(
        b"DEFER fdas"[..],
        serialize_response(PolicyResponse::Defer(b"fdas".to_vec()))[..]
    );
    assert_eq!(
        b"DEFER_IF_REJECT"[..],
        serialize_response(PolicyResponse::DeferIfReject(Vec::new()))[..]
    );
    assert_eq!(
        b"DEFER_IF_REJECT blblblbl"[..],
        serialize_response(PolicyResponse::DeferIfReject(b"blblblbl".to_vec()))[..]
    );
    assert_eq!(
        b"DEFER_IF_PERMIT"[..],
        serialize_response(PolicyResponse::DeferIfPermit(Vec::new()))[..]
    );
    assert_eq!(
        b"DEFER_IF_PERMIT gsdk jf"[..],
        serialize_response(PolicyResponse::DeferIfPermit(b"gsdk jf".to_vec()))[..]
    );
    assert_eq!(
        b"BCC a@b.c"[..],
        serialize_response(PolicyResponse::Bcc(b"a@b.c".to_vec()))[..]
    );
    assert_eq!(
        b"DISCARD"[..],
        serialize_response(PolicyResponse::Discard(Vec::new()))[..]
    );
    assert_eq!(
        b"DISCARD asdffdas"[..],
        serialize_response(PolicyResponse::Discard(b"asdffdas".to_vec()))[..]
    );
    assert_eq!(b"DUNNO"[..], serialize_response(PolicyResponse::Dunno)[..]);
    assert_eq!(b"HOLD"[..], serialize_response(PolicyResponse::Hold(Vec::new()))[..]);
    assert_eq!(
        b"HOLD cmn,sd"[..],
        serialize_response(PolicyResponse::Hold(b"cmn,sd".to_vec()))[..]
    );
    assert_eq!(
        b"REDIRECT a@b.c"[..],
        serialize_response(PolicyResponse::Redirect(b"a@b.c".to_vec()))[..]
    );
    assert_eq!(
        b"INFO some message trololol"[..],
        serialize_response(PolicyResponse::Info(b"some message trololol".to_vec()))[..]
    );
    assert_eq!(
        b"WARN writing something to logs because logging is great and everyone should log everything"[..],
        serialize_response(PolicyResponse::Warn(
            b"writing something to logs because logging is great and everyone should log everything".to_vec()
        ))[..]
    );
}

pub fn handle_connection<'l, HandlerType, HandlerParamType, RS: BufRead, WS: Write>(
    mut reader: RS,
    writer: &mut WS,
    param: &'l HandlerParamType,
) -> Result<(), PostfixPolicyError>
where
    HandlerType: PolicyRequestHandler<'l, HandlerParamType>,
{
    let mut ctx: HandlerType = HandlerType::new(param);

    loop {
        let mut buf: Vec<u8> = vec![];
        if reader.read_until(b'\n', &mut buf)? == 0 {
            return Ok(());
        }

        if buf == b"\n" {
            let result = ctx.response();
            writer.write_all(b"action=")?;
            writer.write_all(&serialize_response(result))?;
            writer.write_all(b"\n\n")?;
            writer.flush()?;
            ctx = HandlerType::new(param);
            continue;
        }

        match buf.iter().position(|&c| c == b'=') {
            None => return Err(PostfixPolicyError::InvalidLine(buf)),
            Some(pos) => {
                let (left, mut right) = buf.split_at(pos);
                if left.len() == 0 || right.len() < 2 {
                    return Err(PostfixPolicyError::InvalidLine(buf));
                }
                right = &right[1..right.len() - 1];
                ctx.parse_line(left, right);
            }
        }
    }
}

pub mod test_helper {
    use super::{handle_connection, PostfixPolicyError, PolicyRequestHandler};
    use std::io::BufReader;
    use std::io::Cursor;

    pub fn handle_connection_response<'l, HandlerType, HandlerParamType>(
        input: &[u8],
        config: &'l HandlerParamType,
    ) -> Result<Vec<u8>, PostfixPolicyError>
    where
        HandlerType: PolicyRequestHandler<'l, HandlerParamType>,
    {
        let reader = BufReader::new(input);
        let mut output = Cursor::new(vec![]);
        handle_connection::<HandlerType, HandlerParamType, _, _>(reader, &mut output, config)?;
        Ok(output.into_inner())
    }
}

#[cfg(test)]
mod tests {

    use super::{PolicyResponse, PostfixPolicyError, PolicyRequestHandler};
    use super::test_helper::handle_connection_response;

    struct DummyRequestHandler {
        found_request: bool,
        client_address: Vec<u8>,
    }
    impl<'l> PolicyRequestHandler<'l, ()> for DummyRequestHandler {
        fn new(_: &()) -> Self {
            Self {
                found_request: false,
                client_address: vec![],
            }
        }
        fn parse_line(&mut self, name: &[u8], value: &[u8]) {
            match name {
                b"request" => self.found_request = true,
                b"client_address" => self.client_address = value.to_vec(),
                _ => {}
            }
        }

        fn response(self) -> PolicyResponse {
            if !self.found_request {
                return PolicyResponse::Reject(Vec::new());
            }
            PolicyResponse::Defer(self.client_address.clone())
        }
    }

    #[test]
    fn test_handle_connection_valid() {
        let input =
            b"request=smtpd_access_policy\nprotocol_state=RCPT\nprotocol_name=ESMTP\nclient_address=131.234.189.14\n\n";
        assert_eq!(
            handle_connection_response::<DummyRequestHandler, _>(input, &()).unwrap(),
            b"action=DEFER 131.234.189.14\n\n"
        );
    }

    #[test]
    fn test_handle_connection_empty() {
        let input = b"\n";
        assert_eq!(
            handle_connection_response::<DummyRequestHandler, _>(input, &()).unwrap(),
            b"action=REJECT\n\n"
        );
    }

    #[test]
    fn test_handle_connection_line_without_eq() {
        let input = b"asdf\n\n";

        assert!(match handle_connection_response::<DummyRequestHandler, _>(input, &()) {
            Err(PostfixPolicyError::InvalidLine(l)) => {
                assert_eq!(&l, b"asdf\n");
                true
            }
            _ => false,
        });
    }

    #[test]
    fn test_handle_connection_line_empty_name() {
        let input = b"=a\n\n";

        assert!(match handle_connection_response::<DummyRequestHandler, _>(input, &()) {
            Err(PostfixPolicyError::InvalidLine(l)) => {
                assert_eq!(&l, b"=a\n");
                true
            }
            _ => false,
        });
    }
}
